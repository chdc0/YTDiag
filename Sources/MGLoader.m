// MGLoader - Option A guest loader skeleton (round 1: injection proof + first dlopen).
//
// What this build does:
//   * proves the dylib was injected into the real YouTube process (log + green chip)
//   * reports the host identity and the container paths the guest is expected at
//   * lists what is actually in Documents/ so an import can be confirmed without guessing
//   * reads the guest's Mach-O header and prints its filetype / ncmds (checks that the
//     Windows-side conversion survived the copy)
//   * offers a LOAD button that does exactly one dlopen() of the guest and prints
//     dlerror() verbatim - the whole point of round 1 is to learn *how* it fails
//
// It must never take the host down: every guest touch is inside @try, and nothing is
// loaded automatically at launch. Stage 0 (chip only) is the default.
//
// Build: see build.sh (clang + iPhoneOS SDK, no Theos). Install name @rpath/MGLoader.dylib.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <arpa/inet.h>

static NSMutableArray<NSString *> *gLines;
static NSLock *gLock;
static NSString *gLogPath;
static UITextView *gTextView;

static void MGLOG(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gLock lock];
    [gLines addObject:s];
    NSUInteger n = gLines.count;
    [gLock unlock];
    NSLog(@"[MG] %@", s);
    if (n % 8 == 0 && gLogPath) {
        [gLines writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
    if (gTextView) {
        dispatch_async(dispatch_get_main_queue(), ^{
            gTextView.text = [gLines componentsJoinedByString:@"\n"];
        });
    }
}

static NSString *GuestRoot(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/MG/guests/tv.twitch-31.7"];
}

static NSString *GuestExec(void) {
    return [GuestRoot() stringByAppendingPathComponent:@"Twitch.app/Twitch"];
}

// --------------------------------------------------------------------------- //
// guest inspection
// --------------------------------------------------------------------------- //

static NSString *DescribeMachO(NSString *path) {
    // header only: the guest executable is 108 MB and this runs at launch
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!fh) return @"missing";
    NSData *d = [fh readDataOfLength:4096];
    [fh closeFile];
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:NULL];
    unsigned long long fileSize = [attrs[NSFileSize] unsignedLongLongValue];
    if (d.length < 32) return [NSString stringWithFormat:@"too short (%lu B)", (unsigned long)d.length];
    const uint8_t *b = d.bytes;
    uint32_t magic = *(const uint32_t *)b;
    if (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
        uint32_t n = ntohl(*(const uint32_t *)(b + 4));
        return [NSString stringWithFormat:@"universal, %u slices, %llu B", n, fileSize];
    }
    if (magic != MH_MAGIC_64) {
        return [NSString stringWithFormat:@"not MH_MAGIC_64 (magic %08x)", magic];
    }
    const struct mach_header_64 *h = (const struct mach_header_64 *)b;
    NSString *type = @"?";
    switch (h->filetype) {
        case MH_EXECUTE: type = @"MH_EXECUTE"; break;
        case MH_DYLIB:   type = @"MH_DYLIB";   break;
        case MH_BUNDLE:  type = @"MH_BUNDLE";  break;
    }
    return [NSString stringWithFormat:@"%@ cputype %d ncmds %u sizeofcmds %u flags %08x %llu B",
            type, h->cputype, h->ncmds, h->sizeofcmds, h->flags, fileSize];
}

static NSString *Entitlement(NSString *key) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return @"<no task>";
    CFTypeRef v = SecTaskCopyValueForEntitlement(task, (__bridge CFStringRef)key, NULL);
    CFRelease(task);
    if (!v) return @"<absent>";
    return [NSString stringWithFormat:@"%@", (__bridge id)v];
}

static void ListDocuments(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSFileManager *fm = NSFileManager.defaultManager;
    BOOL dir = NO;
    if (![fm fileExistsAtPath:docs isDirectory:&dir]) {
        MGLOG(@"Documents/            does not exist");
        return;
    }
    NSArray *top = [fm contentsOfDirectoryAtPath:docs error:NULL];
    MGLOG(@"Documents/            %lu entries: %@", (unsigned long)top.count,
        [top componentsJoinedByString:@", "]);
    NSString *mg = [docs stringByAppendingPathComponent:@"MG"];
    NSArray *mgTop = [fm contentsOfDirectoryAtPath:mg error:NULL];
    if (mgTop) MGLOG(@"Documents/MG/         %@", [mgTop componentsJoinedByString:@", "]);
    NSString *zip = [docs stringByAppendingPathComponent:@"MG/guest.zip"];
    NSDictionary *za = [fm attributesOfItemAtPath:zip error:NULL];
    MGLOG(@"Documents/MG/guest.zip %@", za ? [NSString stringWithFormat:@"%@ B", za[NSFileSize]] : @"absent");
}

// --------------------------------------------------------------------------- //
// the one real experiment
// --------------------------------------------------------------------------- //

static void AttemptLoad(void) {
    NSString *exe = GuestExec();
    MGLOG(@"--- LOAD ---");
    MGLOG(@"guest                 %@", exe);
    MGLOG(@"header                %@", DescribeMachO(exe));

    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm fileExistsAtPath:exe]) {
        MGLOG(@"result                guest executable absent; import it first");
        return;
    }

    // list a few framework entries so a truncated copy is visible before dlopen
    NSString *fw = [GuestRoot() stringByAppendingPathComponent:@"Twitch.app/Frameworks"];
    NSArray *fws = [fm contentsOfDirectoryAtPath:fw error:NULL];
    MGLOG(@"Frameworks/           %lu entries", (unsigned long)fws.count);

    dlerror();  // clear
    void *h = NULL;
    @try {
        h = dlopen(exe.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    } @catch (NSException *e) {
        MGLOG(@"dlopen raised         %@: %@", e.name, e.reason);
        return;
    }
    if (!h) {
        const char *err = dlerror();
        MGLOG(@"dlopen FAILED         %@", err ? [NSString stringWithUTF8String:err] : @"(no dlerror)");
        MGLOG(@"note                  code signature / dependency / pagezero errors all land here");
        return;
    }
    MGLOG(@"dlopen OK             handle %p", h);
    void *mainSym = dlsym(h, "main");
    MGLOG(@"dlsym main            %@", mainSym ? [NSString stringWithFormat:@"%p", mainSym] : @"not exported");
    void *sym2 = dlsym(h, "_main");
    MGLOG(@"dlsym _main           %@", sym2 ? [NSString stringWithFormat:@"%p", sym2] : @"not exported");

    // do NOT call the entry point in round 1: bootstrap is Day 2 work.
}

// --------------------------------------------------------------------------- //
// chip + panel
// --------------------------------------------------------------------------- //

@interface MGVC : UIViewController
@property (nonatomic, strong) UITextView *tv;
@property (nonatomic, strong) UIButton *chip;
@property (nonatomic, strong) UIButton *loadBtn;
@property (nonatomic, strong) UIButton *copyBtn;
@property (nonatomic) BOOL open;
@end

static UIWindow *gWindow;

@implementation MGVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.clearColor;

    self.tv = [[UITextView alloc] initWithFrame:CGRectZero];
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
    self.chip.backgroundColor = [[UIColor colorWithRed:0 green:0.55 blue:0.2 alpha:0.9] colorWithAlphaComponent:0.9];
    [self.chip setTitle:@"MG" forState:UIControlStateNormal];
    [self.chip setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.chip.titleLabel.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    [self.chip addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.chip];

    self.loadBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.loadBtn.backgroundColor = [[UIColor orangeColor] colorWithAlphaComponent:0.9];
    [self.loadBtn setTitle:@"LOAD" forState:UIControlStateNormal];
    [self.loadBtn setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    self.loadBtn.titleLabel.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    [self.loadBtn addTarget:self action:@selector(doLoad) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.loadBtn];

    self.copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.copyBtn.backgroundColor = [[UIColor blueColor] colorWithAlphaComponent:0.85];
    [self.copyBtn setTitle:@"COPY" forState:UIControlStateNormal];
    [self.copyBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.copyBtn.titleLabel.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    [self.copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.copyBtn];

    [self layout];
}

// Named doLoad, not load: -[UIViewController load] is called by UIKit when the view is
// touched for the first time, so overriding it would fire the experiment at launch.
- (void)doLoad {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        AttemptLoad();
        [gLines writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    });
}

- (void)copyLog {
    UIPasteboard.generalPasteboard.string = [gLines componentsJoinedByString:@"\n"];
    [self.copyBtn setTitle:@"COPIED" forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [self.copyBtn setTitle:@"COPY" forState:UIControlStateNormal];
    });
}

- (void)layout {
    CGFloat w = UIScreen.mainScreen.bounds.size.width;
    CGFloat h = UIScreen.mainScreen.bounds.size.height;
    self.chip.frame = CGRectMake(4, 4, 34, 20);
    self.loadBtn.frame = CGRectMake(40, 4, 46, 20);
    self.copyBtn.frame = CGRectMake(88, 4, 46, 20);
    self.tv.frame = CGRectMake(0, 26, w - 8, self.open ? h - 34 : 0);
}

- (void)toggle {
    self.open = !self.open;
    self.tv.hidden = !self.open;
    [self layout];
    if (self.open) {
        gWindow.frame = UIScreen.mainScreen.bounds;
        [gWindow bringSubviewToFront:self.chip];
    } else {
        gWindow.frame = CGRectMake(4, 60, 140, 20);
    }
}

@end

__attribute__((constructor))
static void MGLoaderStart(void) {
    gLock = [NSLock new];
    gLines = [NSMutableArray array];

    MGLOG(@"MGLoader round 1  %@ %@", @__DATE__, @__TIME__);
    MGLOG(@"os                    %@", UIDevice.currentDevice.systemVersion);
    MGLOG(@"device                %@", UIDevice.currentDevice.model);
    MGLOG(@"bundle                %@", NSBundle.mainBundle.bundleIdentifier);
    MGLOG(@"executable            %@", NSBundle.mainBundle.executablePath);
    MGLOG(@"container             %@", NSHomeDirectory());
    MGLOG(@"team id               %@", Entitlement(@"com.apple.developer.team-identifier"));
    MGLOG(@"app id                %@", Entitlement(@"application-identifier"));
    MGLOG(@"get-task-allow        %@", Entitlement(@"get-task-allow"));
    MGLOG(@"keychain groups       %@", Entitlement(@"keychain-access-groups"));

    ListDocuments();
    MGLOG(@"guest root            %@", GuestRoot());
    MGLOG(@"guest header          %@", DescribeMachO(GuestExec()));

    NSURL *caches = [[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory
                                                           inDomains:NSUserDomainMask].firstObject;
    gLogPath = [[caches URLByAppendingPathComponent:@"mgloader.txt"] path];
    [gLines writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) { scene = (UIWindowScene *)s; break; }
        }
        if (!scene) return;
        UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
        w.windowLevel = UIWindowLevelAlert + 50;
        MGVC *vc = [MGVC new];
        w.rootViewController = vc;
        w.frame = CGRectMake(4, 60, 140, 20);
        [w makeKeyAndVisible];
        gWindow = w;
    });
}
