// YTDiag.dylib — read-only diagnostics for YouTube sign-in / stream protection.
//
// Answers three questions on device, with no log retrieval needed:
//   1. What entitlements does the running process actually have?
//   2. Can this process use App Attest at all (isSupported + generateKey + attestKey)?
//   3. Which integrity-token manager does YouTube instantiate (attested vs "no attest")?
//
// Results go to a small red DIAG chip in the top-left; tap it to expand the report,
// tap again to collapse. The same text is written to Library/Caches/ytdiag.txt.
//
// No app state is written, no app logic is replaced. Safe to delete.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static NSMutableArray<NSString *> *gLines;
static NSLock *gLock;
static UITextView *gTextView;
static NSString *gLogPath;
static id gPanelVC;          // YTDiagVC
static BOOL gAutoOpened;

#define LOG(fmt, ...) YTLogLine([NSString stringWithFormat:(fmt), ##__VA_ARGS__])

static void YTLogLine(NSString *line) {
    [gLock lock];
    if (!gLines) gLines = [NSMutableArray array];
    [gLines addObject:line];
    NSString *all = [gLines componentsJoinedByString:@"\n"];
    if (gLogPath) {
        [all writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
    BOOL isUsed = [line hasPrefix:@"USED "];
    BOOL autoOpen = (isUsed && !gAutoOpened);
    if (autoOpen) gAutoOpened = YES;
    [gLock unlock];

    if (gTextView) {
        UITextView *tv = gTextView;
        dispatch_async(dispatch_get_main_queue(), ^{ tv.text = all; });
    }
    if (autoOpen) {
        // The interesting line only appears during sign-in, so reveal the panel itself.
        id vc = gPanelVC;
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([vc respondsToSelector:@selector(expand)]) [vc performSelector:@selector(expand)];
        });
    }
}

// ---------------------------------------------------------------- entitlements

// Resolved at runtime: SecTask.h is not always importable, and a hard link
// failure would make the whole dylib useless.
typedef void *YTSecTaskRef;
static YTSecTaskRef (*pSecTaskCreateFromSelf)(CFAllocatorRef);
static CFTypeRef   (*pSecTaskCopyValueForEntitlement)(YTSecTaskRef, CFStringRef, CFErrorRef *);

static void ResolveSecTask(void) {
    if (pSecTaskCreateFromSelf) return;
    void *h = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!h) return;
    pSecTaskCreateFromSelf = (YTSecTaskRef (*)(CFAllocatorRef))dlsym(h, "SecTaskCreateFromSelf");
    pSecTaskCopyValueForEntitlement =
        (CFTypeRef (*)(YTSecTaskRef, CFStringRef, CFErrorRef *))dlsym(h, "SecTaskCopyValueForEntitlement");
}

static NSString *Entitlement(NSString *key) {
    ResolveSecTask();
    if (!pSecTaskCreateFromSelf || !pSecTaskCopyValueForEntitlement) return @"<no SecTask API>";
    YTSecTaskRef task = pSecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return @"<SecTaskCreateFromSelf failed>";
    CFTypeRef v = pSecTaskCopyValueForEntitlement(task, (__bridge CFStringRef)key, NULL);
    CFRelease((CFTypeRef)task);
    if (!v) return @"<absent>";
    NSString *s;
    if ([(__bridge id)v isKindOfClass:[NSArray class]]) {
        s = [(NSArray *)(__bridge id)v componentsJoinedByString:@", "];
    } else {
        s = [NSString stringWithFormat:@"%@", (__bridge id)v];
    }
    CFRelease(v);
    return s;
}

// ---------------------------------------------------------------- App Attest

static void ProbeAppAttest(void) {
    Class svc = NSClassFromString(@"DCAppAttestService");
    if (!svc) { LOG(@"DCAppAttestService NOT linked"); return; }

    SEL sharedSel = @selector(sharedService);
    if (![svc respondsToSelector:sharedSel]) { LOG(@"sharedService missing"); return; }
    id shared = ((id (*)(id, SEL))[svc methodForSelector:sharedSel])(svc, sharedSel);
    if (!shared) { LOG(@"sharedService returned nil"); return; }

    SEL supSel = @selector(isSupported);
    BOOL supported = ((BOOL (*)(id, SEL))[shared methodForSelector:supSel])(shared, supSel);
    LOG(@"isSupported = %@", supported ? @"YES" : @"NO");

    SEL gen = @selector(generateKeyWithCompletionHandler:);
    if (![shared respondsToSelector:gen]) { LOG(@"generateKey missing"); return; }

    ((void (*)(id, SEL, id))[shared methodForSelector:gen])(shared, gen,
        ^(NSString *keyId, NSError *err) {
            if (err) {
                LOG(@"generateKey FAILED  domain=%@ code=%ld  %@",
                    err.domain, (long)err.code, err.localizedDescription);
                return;
            }
            LOG(@"generateKey ok  keyId=%@", keyId ?: @"<nil>");

            SEL att = NSSelectorFromString(@"attestKey:clientDataHash:completionHandler:");
            if (![shared respondsToSelector:att]) { LOG(@"attestKey missing"); return; }
            NSMutableData *hash = [NSMutableData dataWithLength:32];   // probe only
            ((void (*)(id, SEL, id, id, id))[shared methodForSelector:att])(shared, att, keyId, hash,
                ^(NSData *attestation, NSError *aerr) {
                    if (aerr) {
                        LOG(@"attestKey FAILED  domain=%@ code=%ld  %@",
                            aerr.domain, (long)aerr.code, aerr.localizedDescription);
                    } else {
                        LOG(@"attestKey OK  %lu bytes — a real attestation was produced",
                            (unsigned long)attestation.length);
                    }
                });
        });
}

// ------------------------------------------------- which token manager runs

static NSString *ClassPresence(NSString *name) {
    return NSClassFromString(name) ? @"present" : @"ABSENT";
}

static void DumpSelectors(NSString *name, NSUInteger limit) {
    Class c = NSClassFromString(name);
    if (!c) { LOG(@"%@ -> ABSENT", name); return; }
    unsigned int n = 0;
    Method *ms = class_copyMethodList(c, &n);
    NSMutableArray *sel = [NSMutableArray array];
    for (unsigned i = 0; i < n; i++) [sel addObject:NSStringFromSelector(method_getName(ms[i]))];
    free(ms);
    [sel sortUsingSelector:@selector(compare:)];
    if (sel.count > limit) [sel removeObjectsInRange:NSMakeRange(limit, sel.count - limit)];
    LOG(@"%@", name);
    LOG(@"    %@", [sel componentsJoinedByString:@", "]);
}

// Logs when a class's own -init runs. Only swaps a method the class itself
// implements, so NSObject's -init is never touched.
static void WatchInit(NSString *name) {
    Class c = NSClassFromString(name);
    if (!c) { LOG(@"watch %@ -> ABSENT", name); return; }

    unsigned int n = 0;
    Method *ms = class_copyMethodList(c, &n);
    BOOL owns = NO;
    for (unsigned i = 0; i < n; i++) {
        if (method_getName(ms[i]) == @selector(init)) { owns = YES; break; }
    }
    free(ms);
    if (!owns) { LOG(@"watch %@ -> no own -init", name); return; }

    Method m = class_getInstanceMethod(c, @selector(init));
    IMP orig = method_getImplementation(m);
    method_setImplementation(m, imp_implementationWithBlock(^id(id self) {
        LOG(@"USED %@", name);
        return ((id (*)(id, SEL))orig)(self, @selector(init));
    }));
    LOG(@"watching %@ -init", name);
}

// ---------------------------------------------------------------- panel

@interface YTDiagVC : UIViewController
@property (nonatomic, strong) UITextView *tv;
@property (nonatomic, strong) UIButton *chip;
@property (nonatomic) BOOL open;
@end

static UIWindow *gWindow;

@implementation YTDiagVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.clearColor;
    self.view.frame = UIScreen.mainScreen.bounds;

    self.tv = [[UITextView alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
    self.tv.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.92];
    self.tv.textColor = UIColor.greenColor;
    self.tv.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    self.tv.editable = NO;
    self.tv.alwaysBounceVertical = YES;
    self.tv.textContainerInset = UIEdgeInsetsMake(6, 6, 12, 6);
    self.tv.text = [gLines componentsJoinedByString:@"\n"];
    self.tv.hidden = YES;
    [self.view addSubview:self.tv];
    gTextView = self.tv;

    self.chip = [UIButton buttonWithType:UIButtonTypeSystem];
    self.chip.backgroundColor = [[UIColor redColor] colorWithAlphaComponent:0.85];
    [self.chip setTitle:@"DIAG" forState:UIControlStateNormal];
    [self.chip setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.chip.titleLabel.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    [self.chip addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.chip];

    [self layout];
}

- (void)layout {
    CGFloat w = UIScreen.mainScreen.bounds.size.width;
    CGFloat h = UIScreen.mainScreen.bounds.size.height;
    self.chip.frame = CGRectMake(4, 4, 52, 20);
    self.tv.frame = CGRectMake(0, 26, w - 8, self.open ? h - 34 : 0);
}

- (void)toggle {
    if (self.open) {
        [self collapse];
    } else {
        [self expand];
    }
}

- (void)expand {
    self.open = YES;
    self.tv.hidden = NO;
    [self layout];
    gWindow.frame = UIScreen.mainScreen.bounds;
    [gWindow bringSubviewToFront:self.chip];
}

- (void)collapse {
    self.open = NO;
    self.tv.hidden = YES;
    [self layout];
    gWindow.frame = CGRectMake(4, 60, 52, 20);
}

@end

__attribute__((constructor))
static void YTDiagStart(void) {
    gLock = [NSLock new];

    LOG(@"YTDiag  %@ %@", @__DATE__, @__TIME__);
    LOG(@"os        %@", UIDevice.currentDevice.systemVersion);
    LOG(@"device    %@", UIDevice.currentDevice.model);
    LOG(@"bundle    %@", NSBundle.mainBundle.bundleIdentifier);
    LOG(@"container %@", NSHomeDirectory());

    LOG(@"--- entitlements of this process ---");
    LOG(@"application-identifier  %@", Entitlement(@"application-identifier"));
    LOG(@"team-identifier         %@", Entitlement(@"com.apple.developer.team-identifier"));
    LOG(@"keychain-access-groups  %@", Entitlement(@"keychain-access-groups"));
    LOG(@"appattest-environment   %@", Entitlement(@"com.apple.developer.devicecheck.appattest-environment"));
    LOG(@"get-task-allow          %@", Entitlement(@"get-task-allow"));
    LOG(@"associated-domains      %@", Entitlement(@"com.apple.developer.associated-domains"));

    LOG(@"--- App Attest ---");
    ProbeAppAttest();

    LOG(@"--- integrity token classes ---");
    LOG(@"IGDIntegrityTokenManagerFactory       %@", ClassPresence(@"IGDIntegrityTokenManagerFactory"));
    LOG(@"IGDAppAttest                          %@", ClassPresence(@"IGDAppAttest"));
    LOG(@"IGDAppAttestChallenge                 %@", ClassPresence(@"IGDAppAttestChallenge"));
    LOG(@"IGDNoAppAttestIntegrityTokenManager   %@", ClassPresence(@"IGDNoAppAttestIntegrityTokenManager"));

    LOG(@"--- selectors ---");
    DumpSelectors(@"IGDAppAttest", 25);
    DumpSelectors(@"IGDNoAppAttestIntegrityTokenManager", 25);
    DumpSelectors(@"IGDAppAttestChallenge", 25);
    DumpSelectors(@"IGDIntegrityTokenManagerFactory", 25);
    DumpSelectors(@"SSOIdentityPrivate", 30);

    LOG(@"--- instantiation watch ---");
    WatchInit(@"IGDAppAttest");
    WatchInit(@"IGDNoAppAttestIntegrityTokenManager");
    WatchInit(@"IGDAppAttestChallenge");

    NSURL *caches = [[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory
                                                           inDomains:NSUserDomainMask].firstObject;
    gLogPath = [[caches URLByAppendingPathComponent:@"ytdiag.txt"] path];
    [[gLines componentsJoinedByString:@"\n"] writeToFile:gLogPath
                                              atomically:YES
                                                encoding:NSUTF8StringEncoding
                                                   error:NULL];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) { scene = (UIWindowScene *)s; break; }
        }
        if (!scene) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
        w.windowLevel = UIWindowLevelAlert + 50;
        YTDiagVC *vc = [YTDiagVC new];
        w.rootViewController = vc;
        w.frame = CGRectMake(4, 60, 52, 20);
        [w makeKeyAndVisible];
        gWindow = w;
        gPanelVC = vc;
    });
}
