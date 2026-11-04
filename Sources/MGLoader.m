// MGLoader - Option A guest loader (round 2: log you can always reach, UI that stays out of the
// status bar, one automatic dlopen probe).
//
// Round 1 proved injection but its overlay was unusable: expanding the window moved the hard-coded
// buttons to y=4, i.e. behind the clock, and they could not be tapped. Round 2 fixes that three ways:
//
//   1. The log is written to Documents/mgloader.txt on every line. That folder is visible in the
//      iOS Files app (UIFileSharingEnabled), so the log can be read/shared without the overlay,
//      even if the overlay is broken again.
//   2. The overlay is rebuilt with Auto Layout against safeAreaLayoutGuide, a full-screen panel,
//      and big buttons in a bottom bar. The chip is draggable and a long press copies the log.
//   3. The dlopen probe runs once automatically a few seconds after launch, so nobody has to hit a
//      button to get the answer. A sentinel file makes a crash-on-load happen at most once.
//
// It must never take the host down permanently: every guest touch is inside @try, the probe runs
// behind a sentinel, and nothing is loaded when the guest is absent.
//
// Build: see build.sh (clang + iPhoneOS SDK, no Theos). Install name @rpath/MGLoader.dylib.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <dlfcn.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <arpa/inet.h>

static const char *kRound = "round 2";

static NSMutableArray<NSString *> *gLines;
static NSLock *gLock;
static NSString *gLogPath;          // Documents/mgloader.txt (Files app visible)
static NSString *gMirrorPath;       // Library/Caches/mgloader.txt (kept for compatibility)
static void (^gOnLog)(void);        // set by the panel; called on the main queue
static NSString *gLastLoad = @"not run";

// --------------------------------------------------------------------------- //
// logging
// --------------------------------------------------------------------------- //

static NSString *MGLogText(void) {
    [gLock lock];
    NSString *s = [gLines componentsJoinedByString:@"\n"];
    [gLock unlock];
    return s;
}

// NSArray has no writeToFile:atomically:encoding:error: (only NSString does), so join first.
// Called after every line: the log is small and a crash must not lose the lines before it.
static void MGFlush(void) {
    if (!gLogPath) return;
    NSString *s = MGLogText();
    [s writeToFile:gLogPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    if (gMirrorPath) {
        [s writeToFile:gMirrorPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
}

static void MGLOG(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    [gLock lock];
    [gLines addObject:s];
    [gLock unlock];
    NSLog(@"[MG] %@", s);
    MGFlush();
    if (gOnLog) {
        void (^cb)(void) = gOnLog;
        dispatch_async(dispatch_get_main_queue(), cb);
    }
}

static NSString *MGDocuments(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static NSString *GuestRoot(void) {
    return [MGDocuments() stringByAppendingPathComponent:@"MG/guests/tv.twitch-31.7"];
}

static NSString *GuestExec(void) {
    return [GuestRoot() stringByAppendingPathComponent:@"Twitch.app/Twitch"];
}

// --------------------------------------------------------------------------- //
// guest inspection
// --------------------------------------------------------------------------- //

static NSString *DescribeMachO(NSString *path) {
    // header only: the guest executable is ~108 MB and this runs at launch
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

// SecTask.h is not reliably importable in the iPhoneOS SDK (same finding as YTDiag.m), so the
// two entitlement entry points are resolved from the live Security framework instead of linked.
typedef void *MGSecTaskRef;
static MGSecTaskRef (*pSecTaskCreateFromSelf)(CFAllocatorRef);
static CFTypeRef (*pSecTaskCopyValueForEntitlement)(MGSecTaskRef, CFStringRef, CFErrorRef *);

static void ResolveSecTask(void) {
    if (pSecTaskCreateFromSelf) return;
    void *h = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!h) return;
    pSecTaskCreateFromSelf =
        (MGSecTaskRef (*)(CFAllocatorRef))dlsym(h, "SecTaskCreateFromSelf");
    pSecTaskCopyValueForEntitlement =
        (CFTypeRef (*)(MGSecTaskRef, CFStringRef, CFErrorRef *))dlsym(h, "SecTaskCopyValueForEntitlement");
}

static NSString *Entitlement(NSString *key) {
    ResolveSecTask();
    if (!pSecTaskCreateFromSelf || !pSecTaskCopyValueForEntitlement) return @"<no Security>";
    MGSecTaskRef task = pSecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return @"<no task>";
    CFTypeRef v = pSecTaskCopyValueForEntitlement(task, (__bridge CFStringRef)key, NULL);
    CFRelease(task);
    if (!v) return @"<absent>";
    return [NSString stringWithFormat:@"%@", (__bridge id)v];
}

static void ListDocuments(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *docs = MGDocuments();
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

// forward: the probe reports its outcome on the chip
static void MGSetChip(NSString *title, UIColor *bg);

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
        gLastLoad = @"guest absent";
        MGLOG(@"result                guest executable absent; import it first");
        return;
    }

    NSString *bundle = [GuestRoot() stringByAppendingPathComponent:@"Twitch.app"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                          [bundle stringByAppendingPathComponent:@"Info.plist"]];
    MGLOG(@"guest bundle          %@ (%@, minos %@)", info[@"CFBundleIdentifier"],
          info[@"CFBundleExecutable"], info[@"MinimumOSVersion"]);

    NSString *fw = [bundle stringByAppendingPathComponent:@"Frameworks"];
    NSArray *fws = [fm contentsOfDirectoryAtPath:fw error:NULL];
    MGLOG(@"Frameworks/           %lu entries%@", (unsigned long)fws.count,
          fws.count ? [NSString stringWithFormat:@": %@", [fws componentsJoinedByString:@", "]] : @"");

    dlerror();  // clear
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    void *h = NULL;
    @try {
        h = dlopen(exe.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    } @catch (NSException *e) {
        gLastLoad = @"raised";
        MGLOG(@"dlopen raised         %@: %@", e.name, e.reason);
        return;
    }
    double ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;
    if (!h) {
        const char *err = dlerror();
        gLastLoad = @"FAILED";
        MGLOG(@"dlopen FAILED         %@", err ? [NSString stringWithUTF8String:err] : @"(no dlerror)");
        MGLOG(@"note                  code signature / dependency / pagezero errors all land here");
        MGSetChip(@"MG !", [UIColor colorWithRed:0.72 green:0.1 blue:0.1 alpha:0.95]);
        return;
    }
    gLastLoad = @"OK";
    MGSetChip(@"MG ok", [UIColor colorWithRed:0.1 green:0.35 blue:0.75 alpha:0.95]);
    MGLOG(@"dlopen OK             handle %p in %.0f ms", h, ms);
    void *mainSym = dlsym(h, "main");
    MGLOG(@"dlsym main            %@", mainSym ? [NSString stringWithFormat:@"%p", mainSym] : @"not exported");
    void *sym2 = dlsym(h, "_main");
    MGLOG(@"dlsym _main           %@", sym2 ? [NSString stringWithFormat:@"%p", sym2] : @"not exported");

    // do NOT call the entry point yet: bootstrap is Day 2 work.
}

// One automatic probe, guarded by a sentinel so a guest that crashes the process can only do it
// once. The sentinel lives in Documents because the container survives launches, not installs.
static void MGAutoProbe(void) {
    NSString *sentinel = [MGDocuments() stringByAppendingPathComponent:@"MG/dlopen-in-progress"];
    NSFileManager *fm = NSFileManager.defaultManager;

    MGLOG(@"auto probe            start");
    if ([fm fileExistsAtPath:sentinel]) {
        gLastLoad = @"skipped (previous crash)";
        MGLOG(@"auto probe            previous auto dlopen never returned; skipping");
        MGLOG(@"auto probe            delete Documents/MG/dlopen-in-progress to retry, or tap LOAD");
        return;
    }
    if (![fm fileExistsAtPath:GuestExec()]) {
        gLastLoad = @"guest absent";
        MGLOG(@"auto probe            guest absent, nothing to load");
        return;
    }

    [@"auto dlopen in progress\n" writeToFile:sentinel atomically:YES
                                     encoding:NSUTF8StringEncoding error:NULL];
    MGLOG(@"auto probe            guest present; log flushed, dlopen next");
    MGFlush();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        AttemptLoad();
        [[NSFileManager defaultManager] removeItemAtPath:sentinel error:NULL];
        MGLOG(@"auto probe            returned normally (process survived the load)");
        MGFlush();
    });
}

// --------------------------------------------------------------------------- //
// overlay UI: small chip window + separate full-screen panel window
// --------------------------------------------------------------------------- //

static UIWindow *gChipWindow;
static UIWindow *gPanelWindow;
static UIWindow *gHostWindow;       // the app's own window, restored when the panel closes
static UIButton *gChip;
static UIWindowScene *gScene;

static UIWindowScene *MGGrabScene(void) {
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]] && s.activationState == UISceneActivationStateForegroundActive) {
            return (UIWindowScene *)s;
        }
    }
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)s;
    }
    return nil;
}

static CGFloat MGTopInset(void) {
    CGFloat h = 0;
    if ([gScene respondsToSelector:@selector(statusBarManager)]) {
        UIStatusBarManager *m = gScene.statusBarManager;
        h = CGRectGetHeight(m.statusBarFrame);
    }
    return MAX(h, 24.0);
}

static void MGSetChip(NSString *title, UIColor *bg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [gChip setTitle:title forState:UIControlStateNormal];
        if (bg) gChip.backgroundColor = bg;
    });
}

static NSString *MGStatusLine(void) {
    NSString *guest = DescribeMachO(GuestExec());
    if ([guest isEqualToString:@"missing"]) guest = @"absent";
    return [NSString stringWithFormat:@"guest: %@   dlopen: %@\nlog: %@",
            guest, gLastLoad, gLogPath];
}

static UIButton *MGButton(NSString *title, UIColor *bg, UIColor *fg) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.backgroundColor = bg;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:fg forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    b.layer.cornerRadius = 8;
    b.clipsToBounds = YES;
    return b;
}

@interface MGLogVC : UIViewController
@property (nonatomic, strong) UITextView *tv;
@property (nonatomic, strong) UILabel *status;
@end

@implementation MGLogVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.04 green:0.05 blue:0.06 alpha:1.0];

    UILabel *title = [UILabel new];
    title.text = [NSString stringWithFormat:@"MGLoader  %s", kRound];
    title.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightBold];
    title.textColor = UIColor.whiteColor;

    self.status = [UILabel new];
    self.status.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.status.textColor = [UIColor colorWithRed:1 green:0.78 blue:0.2 alpha:1];
    self.status.numberOfLines = 4;
    self.status.text = MGStatusLine();

    self.tv = [UITextView new];
    self.tv.backgroundColor = [UIColor colorWithWhite:0.09 alpha:1.0];
    self.tv.textColor = [UIColor colorWithRed:0.55 green:1 blue:0.6 alpha:1];
    self.tv.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.tv.editable = NO;
    self.tv.selectable = YES;
    self.tv.alwaysBounceVertical = YES;
    self.tv.textContainerInset = UIEdgeInsetsMake(12, 12, 24, 12);
    self.tv.text = MGLogText();

    UIButton *load = MGButton(@"LOAD", [UIColor colorWithRed:1 green:0.62 blue:0.1 alpha:1], UIColor.blackColor);
    [load addTarget:self action:@selector(doLoad) forControlEvents:UIControlEventTouchUpInside];
    UIButton *copy = MGButton(@"COPY", [UIColor colorWithRed:0.15 green:0.45 blue:1 alpha:1], UIColor.whiteColor);
    [copy addTarget:self action:@selector(doCopy) forControlEvents:UIControlEventTouchUpInside];
    UIButton *share = MGButton(@"SHARE", [UIColor colorWithWhite:0.22 alpha:1], UIColor.whiteColor);
    [share addTarget:self action:@selector(doShare) forControlEvents:UIControlEventTouchUpInside];
    UIButton *close = MGButton(@"CLOSE", [UIColor colorWithWhite:0.32 alpha:1], UIColor.whiteColor);
    [close addTarget:self action:@selector(doClose) forControlEvents:UIControlEventTouchUpInside];

    UIStackView *row1 = [[UIStackView alloc] initWithArrangedSubviews:@[load, copy]];
    UIStackView *row2 = [[UIStackView alloc] initWithArrangedSubviews:@[share, close]];
    for (UIStackView *r in @[row1, row2]) {
        r.axis = UILayoutConstraintAxisHorizontal;
        r.distribution = UIStackViewDistributionFillEqually;
        r.spacing = 8;
    }
    UIStackView *bar = [[UIStackView alloc] initWithArrangedSubviews:@[row1, row2]];
    bar.axis = UILayoutConstraintAxisVertical;
    bar.distribution = UIStackViewDistributionFillEqually;
    bar.spacing = 8;

    for (UIView *v in @[title, self.status, self.tv, bar]) {
        v.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:v];
    }

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:safe.topAnchor constant:12],
        [title.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [title.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [self.status.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:6],
        [self.status.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [self.status.trailingAnchor constraintEqualToAnchor:title.trailingAnchor],

        [self.tv.topAnchor constraintEqualToAnchor:self.status.bottomAnchor constant:10],
        [self.tv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.tv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.tv.bottomAnchor constraintEqualToAnchor:bar.topAnchor constant:-8],

        [bar.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [bar.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [bar.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-10],
        [row1.heightAnchor constraintEqualToConstant:46],
        [row2.heightAnchor constraintEqualToConstant:46],
    ]];

}

- (void)refresh {
    NSString *text = MGLogText();
    self.tv.text = text;
    if (text.length) {
        [self.tv scrollRangeToVisible:NSMakeRange(text.length - 1, 1)];
    }
    self.status.text = MGStatusLine();
}

// Named doLoad, not load: -[UIViewController load] is called by UIKit the first time the view is
// touched, so overriding it would fire the experiment at launch.
- (void)doLoad {
    self.status.text = @"loading, this can take a few seconds ...";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        AttemptLoad();
        MGFlush();
        dispatch_async(dispatch_get_main_queue(), ^{ [self refresh]; });
    });
}

- (void)doCopy {
    UIPasteboard.generalPasteboard.string = MGLogText();
    NSString *old = self.status.text;
    self.status.text = @"copied to the clipboard";
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ self.status.text = old; });
}

- (void)doShare {
    NSURL *url = [NSURL fileURLWithPath:gLogPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:gLogPath]) {
        self.status.text = @"log file missing";
        return;
    }
    UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:@[url]
                                                                    applicationActivities:nil];
    avc.popoverPresentationController.sourceView = self.view;
    avc.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(self.view.bounds),
                                                             CGRectGetMaxY(self.view.bounds) - 60, 1, 1);
    [self presentViewController:avc animated:YES completion:nil];
}

- (void)doClose {
    gPanelWindow.hidden = YES;
    gChipWindow.hidden = NO;
    gOnLog = nil;
    if (!gHostWindow || gHostWindow.hidden) {
        gHostWindow = nil;
        for (UIWindow *w in gScene.windows) {
            if (w.windowLevel == UIWindowLevelNormal) { gHostWindow = w; break; }
        }
    }
    [gHostWindow makeKeyWindow];
}

@end

@interface MGChipVC : UIViewController
@end

@implementation MGChipVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.clearColor;

    gChip = [UIButton buttonWithType:UIButtonTypeSystem];
    gChip.backgroundColor = [UIColor colorWithRed:0 green:0.55 blue:0.2 alpha:0.95];
    [gChip setTitle:@"MG" forState:UIControlStateNormal];
    [gChip setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    gChip.titleLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold];
    gChip.layer.cornerRadius = 8;
    gChip.layer.borderWidth = 1;
    gChip.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.55].CGColor;
    gChip.clipsToBounds = YES;
    gChip.frame = self.view.bounds;
    gChip.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [gChip addTarget:self action:@selector(openPanel) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:gChip];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(move:)];
    [gChip addGestureRecognizer:pan];

    UILongPressGestureRecognizer *press =
        [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(copyFromChip:)];
    press.minimumPressDuration = 0.7;
    [gChip addGestureRecognizer:press];
}

- (void)move:(UIPanGestureRecognizer *)g {
    CGPoint d = [g translationInView:nil];
    CGRect f = gChipWindow.frame;
    f.origin.x += d.x;
    f.origin.y += d.y;
    gChipWindow.frame = f;
    [g setTranslation:CGPointZero inView:nil];
}

// Emergency path: a long press copies the log without opening the panel at all.
- (void)copyFromChip:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    UIPasteboard.generalPasteboard.string = MGLogText();
    MGSetChip(@"MG ok", [UIColor colorWithRed:0.1 green:0.4 blue:0.8 alpha:1]);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        MGSetChip(@"MG", [UIColor colorWithRed:0 green:0.55 blue:0.2 alpha:0.95]);
    });
}

- (void)openPanel {
    if (!gPanelWindow) {
        CGRect b = gScene.coordinateSpace.bounds;
        gPanelWindow = [[UIWindow alloc] initWithWindowScene:gScene];
        gPanelWindow.frame = b;
        gPanelWindow.windowLevel = UIWindowLevelAlert + 100;
        gPanelWindow.backgroundColor = UIColor.blackColor;
        gPanelWindow.rootViewController = [MGLogVC new];
    }
    gChipWindow.hidden = YES;
    gPanelWindow.hidden = NO;
    [gPanelWindow makeKeyAndVisible];

    MGLogVC *vc = (MGLogVC *)gPanelWindow.rootViewController;
    if ([vc isKindOfClass:[MGLogVC class]]) {
        __weak MGLogVC *weakVC = vc;
        gOnLog = ^{
            __strong MGLogVC *me = weakVC;
            [me refresh];
        };
        [vc refresh];
    }
}

@end

// --------------------------------------------------------------------------- //
// entry point
// --------------------------------------------------------------------------- //

__attribute__((constructor))
static void MGLoaderStart(void) {
    gLock = [NSLock new];
    gLines = [NSMutableArray array];

    NSString *docs = MGDocuments();
    gLogPath = [docs stringByAppendingPathComponent:@"mgloader.txt"];
    [[NSFileManager defaultManager] createDirectoryAtPath:[docs stringByAppendingPathComponent:@"MG"]
                              withIntermediateDirectories:YES attributes:nil error:NULL];
    NSURL *caches = [[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory
                                                           inDomains:NSUserDomainMask].firstObject;
    gMirrorPath = [[caches URLByAppendingPathComponent:@"mgloader.txt"] path];

    MGLOG(@"MGLoader %s  %@ %@", kRound, @__DATE__, @__TIME__);
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
    MGLOG(@"log file              %@", gLogPath);
    MGFlush();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        gScene = MGGrabScene();
        if (!gScene) return;

        for (UIWindow *w in gScene.windows) {
            if (w.windowLevel == UIWindowLevelNormal) { gHostWindow = w; break; }
        }

        gChipWindow = [[UIWindow alloc] initWithWindowScene:gScene];
        gChipWindow.windowLevel = UIWindowLevelAlert + 10;
        gChipWindow.backgroundColor = UIColor.clearColor;
        gChipWindow.rootViewController = [MGChipVC new];
        CGFloat top = MGTopInset();
        gChipWindow.frame = CGRectMake(8, top + 6, 54, 30);
        gChipWindow.hidden = NO;

        MGLOG(@"overlay               chip at (8, %.0f), 54x30", top + 6);
        MGFlush();
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ MGAutoProbe(); });
}
