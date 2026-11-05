// MGLoader - Option A guest loader (round 13: single-flight LOAD, preserved per-run log, and
// checkpoints around the SharePlay shim and guest scene callback).
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
// Round 3 proved SideStore signs the mode-B guest. Round 4 proved RTLD_LAZY defers an unresolved
// Reanimated constructor (it does not supply it). Round 5 found the guest delegate/factory classes.
// Round 6's delegate callback trapped because Bundle.main was YouTube; round 7 fixed that with a
// thread-scoped NSBundle.mainBundle override and confirmed TWAppDelegate returned YES while the
// host state stayed unchanged. Round 8 captured the host's real UISceneConnectionOptions and
// reached Twitch.SceneDelegate. That callback asked YTAppDelegate for Twitch-only setUpSharePlay.
// Round 9 temporarily assigned TWAppDelegate during the scene callback and created the first
// TWWindow/Twitch.RootViewController, but later backgrounding crashed. Round 10 pinned YTAppDelegate,
// but scene initialization still trapped and UIKit state restoration remained unstable. Round 11
// confirmed the host lacks Twitch's app-group entitlement and the group's container URL is nil.
// Round 12 showed the SharePlay skip alone did not stabilize scene startup; its top seven Twitch
// frames matched the r10 scene trap. Round 13 keeps the r12 behavior, but adds diagnostics only:
// 1. LOAD becomes single-flight and manual-only, so an automatic probe cannot race a tapped LOAD.
// 2. The previous run's mgloader.txt is preserved as mgloader.previous.txt before truncation.
// 3. Checkpoints log shim installation/invocation and every guest scene callback stage.
// No UIApplicationMain, fabricated scene/options, or UIApplication.delegate swap.
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
#include <string.h>

static const char *kRound = "round 13";

static NSMutableArray<NSString *> *gLines;
static NSLock *gLock;
static NSString *gLogPath;          // Documents/mgloader.txt (Files app visible)
static NSString *gMirrorPath;       // Library/Caches/mgloader.txt (kept for compatibility)
static void (^gOnLog)(void);        // set by the panel; called on the main queue
static NSString *gLastLoad = @"not run";
static IMP gOriginalMainBundleIMP;
static NSString * const kGuestMainBundleThreadKey = @"MGLoader.ThreadGuestMainBundle";
static NSString * const kGuestSharePlaySkipThreadKey = @"MGLoader.SkipGuestSharePlay";
static BOOL gLoadInProgress = NO;
static id gGuestAppDelegate;
static id gGuestSceneDelegate;
static UIScene *gHostConnectedScene;
static UISceneSession *gHostSceneSession;
static UISceneConnectionOptions *gHostSceneConnectionOptions;
static IMP gOriginalHostSceneWillConnectIMP;
static BOOL gHostSceneOptionsCaptureInstalled;

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
    static NSString *root;
    if (root) return root;

    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *rel = @"MG/guests/tv.twitch-31.7";
    NSString *bundleRoot = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:rel];
    NSString *docsRoot = [MGDocuments() stringByAppendingPathComponent:rel];
    NSString *bundleExe = [bundleRoot stringByAppendingPathComponent:@"Twitch.app/Twitch"];
    NSString *override = [MGDocuments() stringByAppendingPathComponent:@"MG/use-documents"];

    // mode B unless the bundle has no payload or the spike asks for the Documents import
    if (![fm fileExistsAtPath:override] && [fm fileExistsAtPath:bundleExe]) {
        root = bundleRoot;
    } else {
        root = docsRoot;
    }
    return root;
}

static NSString *GuestMode(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *rel = @"MG/guests/tv.twitch-31.7";
    BOOL bundled = [fm fileExistsAtPath:[[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:rel]
                                         stringByAppendingPathComponent:@"Twitch.app/Twitch"]];
    BOOL docs = [fm fileExistsAtPath:[[MGDocuments() stringByAppendingPathComponent:rel]
                                      stringByAppendingPathComponent:@"Twitch.app/Twitch"]];
    BOOL override = [fm fileExistsAtPath:[MGDocuments() stringByAppendingPathComponent:@"MG/use-documents"]];
    if (override) return @"C (documents, forced by MG/use-documents)";
    if (bundled) return docs ? @"B (app bundle; a Documents copy is also present)" : @"B (app bundle)";
    return @"C (documents; no payload in the app bundle)";
}

static NSString *GuestRoots(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *rel = @"MG/guests/tv.twitch-31.7";
    NSString *b = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:rel];
    NSString *d = [MGDocuments() stringByAppendingPathComponent:rel];
    return [NSString stringWithFormat:@"bundle %@, documents %@",
            [fm fileExistsAtPath:[b stringByAppendingPathComponent:@"Twitch.app/Twitch"]] ? @"present" : @"absent",
            [fm fileExistsAtPath:[d stringByAppendingPathComponent:@"Twitch.app/Twitch"]] ? @"present" : @"absent"];
}

static NSString *GuestExec(void) {
    return [GuestRoot() stringByAppendingPathComponent:@"Twitch.app/Twitch"];
}

// Who signed the guest? On iOS 26+ that is the difference between "loads" and EPERM, and dlerror
// does not say. Reads the load commands and at most 64 KB of the signature blob: CodeDirectory
// flags (0x2 = ad-hoc), CMS presence, team id and identifier - not the pages.
static NSString *DescribeSignature(NSString *path) {
    @try {
        NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:path];
        if (!fh) return @"missing";
        // LC_CODE_SIGNATURE is the last command of a linker-produced image; the guest's table is
        // 18,576 B, so 8 KB would miss it and report a false "no LC_CODE_SIGNATURE".
        NSData *head = [fh readDataOfLength:65536];
        if (head.length < 32) { [fh closeFile]; return @"too short"; }
        const uint8_t *b = head.bytes;
        if (*(const uint32_t *)b != MH_MAGIC_64) { [fh closeFile]; return @"not a thin arm64 image"; }

        uint32_t ncmds = *(const uint32_t *)(b + 16);
        uint32_t off = 32, dataoff = 0, datasize = 0;
        for (uint32_t i = 0; i < ncmds && off + 16 <= head.length; i++) {
            uint32_t cmd = *(const uint32_t *)(b + off);
            uint32_t size = *(const uint32_t *)(b + off + 4);
            if (size < 8) break;
            if (cmd == LC_CODE_SIGNATURE) {
                dataoff = *(const uint32_t *)(b + off + 8);
                datasize = *(const uint32_t *)(b + off + 12);
            }
            off += size;
        }
        if (!dataoff || !datasize) { [fh closeFile]; return @"no LC_CODE_SIGNATURE"; }

        [fh seekToFileOffset:dataoff];
        NSData *blob = [fh readDataOfLength:65536];
        [fh closeFile];
        if (blob.length < 16) return @"signature blob unreadable";
        const uint8_t *p = blob.bytes;
        uint32_t superMagic = ntohl(*(const uint32_t *)p);
        if (superMagic != 0xfade0cc0) {
            return [NSString stringWithFormat:@"bad SuperBlob magic %08x", superMagic];
        }

        uint32_t count = ntohl(*(const uint32_t *)(p + 8));
        int cdOff = -1;
        BOOL cms = NO;
        for (uint32_t i = 0; i < count && 12 + (i + 1) * 8 <= blob.length; i++) {
            uint32_t type = ntohl(*(const uint32_t *)(p + 12 + i * 8));
            uint32_t at = ntohl(*(const uint32_t *)(p + 16 + i * 8));
            if (type == 0) cdOff = (int)at;
            else if (type == 0x10000) cms = YES;
        }
        if (cdOff < 0 || cdOff + 56 > (int)blob.length) return @"no CodeDirectory";
        const uint8_t *cd = p + cdOff;
        if (ntohl(*(const uint32_t *)cd) != 0xfade0c02) return @"bad CodeDirectory magic";

        uint32_t version = ntohl(*(const uint32_t *)(cd + 8));
        uint32_t flags = ntohl(*(const uint32_t *)(cd + 12));

        NSString *team = @"-";
        if (version >= 0x20200) {
            uint32_t teamOff = ntohl(*(const uint32_t *)(cd + 48));
            if (teamOff && cdOff + (int)teamOff < (int)blob.length) {
                const char *s = (const char *)cd + teamOff;
                size_t room = blob.length - (cdOff + teamOff);
                size_t n = strnlen(s, room);
                if (n > 0 && n < room && [NSString stringWithUTF8String:s]) {
                    team = [NSString stringWithUTF8String:s];
                }
            }
        }
        NSString *ident = @"-";
        uint32_t identOff = ntohl(*(const uint32_t *)(cd + 20));
        if (identOff && cdOff + (int)identOff < (int)blob.length) {
            const char *s = (const char *)cd + identOff;
            size_t room = blob.length - (cdOff + identOff);
            size_t n = strnlen(s, room);
            if (n > 0 && n < room && [NSString stringWithUTF8String:s]) {
                ident = [NSString stringWithUTF8String:s];
            }
        }
        return [NSString stringWithFormat:@"%@ cms=%@ team=%@ ident=%@ flags=0x%08x cd=0x%06x datasize=%u",
                (flags & 0x2) ? @"adhoc" : @"cert", cms ? @"yes" : @"no", team, ident, flags, version, datasize];
    } @catch (NSException *e) {
        return [NSString stringWithFormat:@"probe raised %@", e.name];
    }
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

// Read-only runtime reconnaissance. Do not allocate/init guest delegates here: their initializers
// may assume UIApplicationMain has already run. The class and method metadata tells the bootstrap
// round which entry points exist without changing the host's UIApplication or scene.
static NSString *DescribeRuntimeClass(NSString *name) {
    Class cls = NSClassFromString(name);
    if (!cls) return @"not registered";

    Class super = class_getSuperclass(cls);
    BOOL appDelegate = class_conformsToProtocol(cls, @protocol(UIApplicationDelegate));
    BOOL sceneDelegate = class_conformsToProtocol(cls, @protocol(UISceneDelegate));
    NSArray<NSString *> *candidates = @[
        @"application:didFinishLaunchingWithOptions:",
        @"application:configurationForConnectingSceneSession:options:",
        @"applicationDidBecomeActive:",
        @"scene:willConnectToSession:options:",
        @"sceneDidBecomeActive:",
        @"sceneWillEnterForeground:",
        @"sceneDidEnterBackground:"
    ];
    NSMutableArray<NSString *> *methods = [NSMutableArray array];
    for (NSString *candidate in candidates) {
        if (class_getInstanceMethod(cls, NSSelectorFromString(candidate))) {
            [methods addObject:candidate];
        }
    }
    return [NSString stringWithFormat:@"found class=%s superclass=%s UIApplicationDelegate=%@ UISceneDelegate=%@ methods=[%@]",
            class_getName(cls), super ? class_getName(super) : "<none>",
            appDelegate ? @"yes" : @"no", sceneDelegate ? @"yes" : @"no",
            [methods componentsJoinedByString:@", "]];
}

static NSString *RuntimeObjectName(id object) {
    return object ? NSStringFromClass([object class]) : @"nil";
}

// NSBundle.mainBundle is process-global by default. During the guest lifecycle callback only, let
// calls on the current thread see Twitch.app; every other thread and all calls after the callback
// continue to see the original YouTube bundle.
static NSBundle *MGScopedMainBundle(id self, SEL cmd) {
    NSBundle *scoped = NSThread.currentThread.threadDictionary[kGuestMainBundleThreadKey];
    if (scoped) return scoped;
    IMP original = gOriginalMainBundleIMP;
    return original ? ((NSBundle *(*)(id, SEL))original)(self, cmd) : nil;
}

static BOOL MGInstallMainBundleScope(void) {
    static dispatch_once_t once;
    static BOOL installed = NO;
    dispatch_once(&once, ^{
        Method method = class_getClassMethod([NSBundle class], @selector(mainBundle));
        if (!method) return;
        gOriginalMainBundleIMP = method_setImplementation(method, (IMP)MGScopedMainBundle);
        installed = (gOriginalMainBundleIMP != NULL);
    });
    return installed;
}

// SharePlay's setUpSharePlay requires Twitch's unavailable App Group. Add a narrow shim to the host
// delegate only if it does not already respond. The method does nothing only while the guest scene
// callback's thread-local opt-out flag is active.
static void MGSkipGuestSharePlay(id self, SEL cmd) {
    if ([NSThread.currentThread.threadDictionary[kGuestSharePlaySkipThreadKey] boolValue]) {
        MGLOG(@"guest SharePlay shim    invoked; no-op for this guest scene callback");
    } else {
        MGLOG(@"guest SharePlay shim    call outside guest scene callback; preserving unrecognized-selector behavior");
        [self doesNotRecognizeSelector:cmd];
    }
}

static BOOL MGInstallGuestSharePlayShim(void) {
    id hostDelegate = UIApplication.sharedApplication.delegate;
    if (!hostDelegate) return NO;
    Class cls = object_getClass(hostDelegate);
    SEL selector = NSSelectorFromString(@"setUpSharePlay");
    Method existing = class_getInstanceMethod(cls, selector);
    if (existing) return method_getImplementation(existing) == (IMP)MGSkipGuestSharePlay;
    return class_addMethod(cls, selector, (IMP)MGSkipGuestSharePlay, "v16@0:8");
}

// Capture UIKit's real, immutable connection-options object for the host scene. The wrapper stores
// the arguments and forwards the original YTSceneDelegate implementation unchanged; we never
// fabricate UISceneConnectionOptions (UIKit marks its public init/new unavailable).
static void MGHostSceneWillConnect(id self, SEL cmd, UIScene *scene,
                                   UISceneSession *session, UISceneConnectionOptions *options) {
    gHostConnectedScene = scene;
    gHostSceneSession = session;
    gHostSceneConnectionOptions = options;

    IMP original = gOriginalHostSceneWillConnectIMP;
    if (original) {
        ((void (*)(id, SEL, UIScene *, UISceneSession *, UISceneConnectionOptions *))original)
            (self, cmd, scene, session, options);
    }

    NSUInteger urls = options.URLContexts.count;
    NSUInteger activities = options.userActivities.count;
    MGLOG(@"host scene options captured scene=%@ session=%@ options=%@ URLs=%lu activities=%lu source=%@ handoff=%@",
          RuntimeObjectName(scene), session.persistentIdentifier, RuntimeObjectName(options),
          (unsigned long)urls, (unsigned long)activities,
          options.sourceApplication ?: @"<nil>", options.handoffUserActivityType ?: @"<nil>");
}

static BOOL MGInstallHostSceneOptionsCapture(void) {
    if (gHostSceneOptionsCaptureInstalled) return YES;
    Class cls = NSClassFromString(@"YTSceneDelegate");
    if (!cls) return NO;
    SEL selector = @selector(scene:willConnectToSession:options:);
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) return NO;

    IMP original = method_getImplementation(method);
    if (original == (IMP)MGHostSceneWillConnect) {
        gHostSceneOptionsCaptureInstalled = YES;
        return YES;
    }
    gOriginalHostSceneWillConnectIMP = method_setImplementation(method, (IMP)MGHostSceneWillConnect);
    gHostSceneOptionsCaptureInstalled = (gOriginalHostSceneWillConnectIMP != NULL);
    return gHostSceneOptionsCaptureInstalled;
}

// Initialize the guest app delegate once per process. An in-progress marker remains only on failure;
// successful initialization keeps the instance alive for the following scene callback.
static BOOL AttemptGuestAppDelegateLaunch(void) {
    if (gGuestAppDelegate) return YES;
    MGLOG(@"guest launch callback   entering");
    NSString *attempted = [MGDocuments() stringByAppendingPathComponent:@"MG/guest-appdelegate-in-progress-r13"];
    NSFileManager *fm = NSFileManager.defaultManager;
    if ([fm fileExistsAtPath:attempted]) {
        MGLOG(@"guest launch callback  skipped (round-13 prior attempt did not finish; marker retained)");
        return NO;
    }

    // Write before class realization/init/callback: a crash leaves a persistent marker so a new
    // process cannot silently rerun the guest's launch sequence.
    [@"TWAppDelegate launch callback in progress\n" writeToFile:attempted atomically:YES
                                                      encoding:NSUTF8StringEncoding error:NULL];
    __block BOOL callbackSucceeded = NO;
    dispatch_block_t invoke = ^{
        Class cls = NSClassFromString(@"TWAppDelegate");
        if (!cls) {
            MGLOG(@"guest launch callback  TWAppDelegate not registered");
            return;
        }

        UIApplication *app = UIApplication.sharedApplication;
        id hostDelegateBefore = app.delegate;
        NSUInteger windowsBefore = app.windows.count;
        NSUInteger scenesBefore = app.connectedScenes.count;
        NSBundle *hostBundleBefore = NSBundle.mainBundle;
        MGLOG(@"guest callback before  appDelegate=%@ windows=%lu scenes=%lu state=%ld",
              RuntimeObjectName(hostDelegateBefore), (unsigned long)windowsBefore,
              (unsigned long)scenesBefore, (long)app.applicationState);

        NSString *guestBundlePath = [[GuestRoot() stringByAppendingPathComponent:@"Twitch.app"]
                                     stringByStandardizingPath];
        NSBundle *guestBundle = [NSBundle bundleWithPath:guestBundlePath];
        if (!guestBundle) {
            MGLOG(@"guest main bundle     could not create NSBundle at %@", guestBundlePath);
            return;
        }
        if (!MGInstallMainBundleScope()) {
            MGLOG(@"guest main bundle     could not install scoped +[NSBundle mainBundle] wrapper");
            return;
        }

        NSMutableDictionary *threadDictionary = NSThread.currentThread.threadDictionary;
        id priorScopedBundle = threadDictionary[kGuestMainBundleThreadKey];
        threadDictionary[kGuestMainBundleThreadKey] = guestBundle;
        @try {
            NSBundle *observedMainBundle = NSBundle.mainBundle;
            id groupName = [observedMainBundle objectForInfoDictionaryKey:@"TWAppGroupName"];
            MGLOG(@"guest main bundle     original=%@ scoped=%@ TWAppGroupName=%@",
                  hostBundleBefore.bundlePath, observedMainBundle.bundlePath,
                  groupName ?: @"<absent>");
            if (![observedMainBundle.bundlePath isEqualToString:guestBundle.bundlePath]) {
                MGLOG(@"guest launch callback  scoped main bundle did not take effect; callback not called");
                return;
            }
            if (![groupName isKindOfClass:[NSString class]] || [groupName length] == 0) {
                MGLOG(@"guest launch callback  guest Info.plist has no TWAppGroupName; callback not called");
                return;
            }

            id instance = [[cls alloc] init];
            if (!instance) {
                MGLOG(@"guest launch callback  TWAppDelegate init returned nil");
                return;
            }
            SEL selector = @selector(application:didFinishLaunchingWithOptions:);
            if (![instance respondsToSelector:selector]) {
                MGLOG(@"guest launch callback  selector missing on %@", RuntimeObjectName(instance));
                return;
            }

            id<UIApplicationDelegate> guestDelegate = (id<UIApplicationDelegate>)instance;
            BOOL result = [guestDelegate application:app didFinishLaunchingWithOptions:nil];
            id hostDelegateAfter = app.delegate;
            MGLOG(@"guest launch callback  returned %@ instance=%@",
                  result ? @"YES" : @"NO", RuntimeObjectName(instance));
            MGLOG(@"guest callback after   appDelegate=%@ unchanged=%@ windows=%lu scenes=%lu state=%ld",
                  RuntimeObjectName(hostDelegateAfter), hostDelegateAfter == hostDelegateBefore ? @"yes" : @"NO",
                  (unsigned long)app.windows.count, (unsigned long)app.connectedScenes.count,
                  (long)app.applicationState);
            if (result) {
                gGuestAppDelegate = instance;
                callbackSucceeded = YES;
                [fm removeItemAtPath:attempted error:NULL];
            }
        } @catch (NSException *e) {
            MGLOG(@"guest launch callback  raised %@: %@", e.name, e.reason);
        } @finally {
            if (priorScopedBundle) threadDictionary[kGuestMainBundleThreadKey] = priorScopedBundle;
            else [threadDictionary removeObjectForKey:kGuestMainBundleThreadKey];
            MGLOG(@"host main bundle restored %@ expected=%@",
                  NSBundle.mainBundle.bundlePath, hostBundleBefore.bundlePath);
        }
    };

    // UIKit lifecycle callbacks belong on main. LOAD may be tapped on main; the automatic probe
    // invokes AttemptLoad from a worker, where dispatch_sync is safe because the main queue is live.
    if (NSThread.isMainThread) invoke();
    else dispatch_sync(dispatch_get_main_queue(), invoke);
    return callbackSucceeded;
}

static BOOL AttemptGuestSceneConnect(void) {
    MGLOG(@"guest scene callback   entering");
    if (gGuestSceneDelegate) {
        MGLOG(@"guest scene callback   skipped (scene delegate already connected in this process)");
        return YES;
    }
    if (!gGuestAppDelegate) {
        MGLOG(@"guest scene callback   skipped (TWAppDelegate launch did not succeed)");
        return NO;
    }
    if (!gHostSceneOptionsCaptureInstalled || !gHostConnectedScene || !gHostSceneSession ||
        !gHostSceneConnectionOptions) {
        MGLOG(@"guest scene callback   skipped (no real host UIScene/options captured)");
        return NO;
    }

    UISceneConnectionOptions *options = gHostSceneConnectionOptions;
    NSUInteger urlCount = options.URLContexts.count;
    NSUInteger activityCount = options.userActivities.count;
    NSString *sourceApplication = options.sourceApplication;
    NSString *handoffType = options.handoffUserActivityType;
    BOOL hasShortcut = (options.shortcutItem != nil);
    BOOL hasNotification = (options.notificationResponse != nil);
    BOOL hasCloudShare = (options.cloudKitShareMetadata != nil);
    MGLOG(@"host scene options     urls=%lu activities=%lu source=%@ handoff=%@ shortcut=%@ notification=%@ cloudShare=%@",
          (unsigned long)urlCount, (unsigned long)activityCount,
          sourceApplication ?: @"<nil>", handoffType ?: @"<nil>",
          hasShortcut ? @"yes" : @"no", hasNotification ? @"yes" : @"no",
          hasCloudShare ? @"yes" : @"no");
    if (urlCount || activityCount || sourceApplication.length || handoffType.length ||
        hasShortcut || hasNotification || hasCloudShare) {
        MGLOG(@"guest scene callback   skipped (host launch carried user-specific connection options)");
        return NO;
    }

    NSString *attempted = [MGDocuments() stringByAppendingPathComponent:@"MG/guest-scene-in-progress-r13"];
    NSFileManager *fm = NSFileManager.defaultManager;
    if ([fm fileExistsAtPath:attempted]) {
        MGLOG(@"guest scene callback   skipped (round-13 marker remains from an incomplete attempt)");
        return NO;
    }

    Class cls = NSClassFromString(@"Twitch.SceneDelegate");
    if (!cls) {
        MGLOG(@"guest scene callback   Twitch.SceneDelegate not registered");
        return NO;
    }
    SEL selector = @selector(scene:willConnectToSession:options:);
    if (![cls instancesRespondToSelector:selector]) {
        MGLOG(@"guest scene callback   willConnect selector missing");
        return NO;
    }

    __block BOOL sharePlayShimInstalled = NO;
    dispatch_block_t installSharePlayShim = ^{
        sharePlayShimInstalled = MGInstallGuestSharePlayShim();
    };
    if (NSThread.isMainThread) installSharePlayShim();
    else dispatch_sync(dispatch_get_main_queue(), installSharePlayShim);
    if (!sharePlayShimInstalled) {
        MGLOG(@"guest scene callback   could not install no-op setUpSharePlay shim on the host delegate");
        return NO;
    }
    MGLOG(@"guest SharePlay shim    installed on %@; no-op scoped to scene callback",
          RuntimeObjectName(UIApplication.sharedApplication.delegate));

    // The versioned marker is written before class realization/init/callback. Leave it in place on
    // a crash; remove it only after the callback returns normally.
    [@"Twitch.SceneDelegate willConnect in progress with captured host options\n"
        writeToFile:attempted atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    MGLOG(@"guest scene callback   marker written");
    __block BOOL connected = NO;
    dispatch_block_t connect = ^{
        UIScene *scene = gHostConnectedScene;
        UISceneSession *session = gHostSceneSession;
        if (![scene isKindOfClass:[UIWindowScene class]]) {
            MGLOG(@"guest scene callback   captured scene is not UIWindowScene: %@", RuntimeObjectName(scene));
            return;
        }

        UIApplication *app = UIApplication.sharedApplication;
        id appDelegateBefore = app.delegate;
        id sceneDelegateBefore = scene.delegate;
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        NSUInteger windowsBefore = app.windows.count;
        NSUInteger sceneWindowsBefore = windowScene.windows.count;
        MGLOG(@"guest scene before     appDelegate=%@ sceneDelegate=%@ windows=%lu sceneWindows=%lu state=%ld",
              RuntimeObjectName(appDelegateBefore), RuntimeObjectName(sceneDelegateBefore),
              (unsigned long)windowsBefore, (unsigned long)sceneWindowsBefore,
              (long)app.applicationState);

        NSString *guestBundlePath = [[GuestRoot() stringByAppendingPathComponent:@"Twitch.app"]
                                     stringByStandardizingPath];
        NSBundle *guestBundle = [NSBundle bundleWithPath:guestBundlePath];
        if (!guestBundle || !MGInstallMainBundleScope()) {
            MGLOG(@"guest scene callback   cannot establish guest NSBundle.mainBundle scope");
            return;
        }

        NSMutableDictionary *threadDictionary = NSThread.currentThread.threadDictionary;
        id priorScopedBundle = threadDictionary[kGuestMainBundleThreadKey];
        id priorSharePlaySkip = threadDictionary[kGuestSharePlaySkipThreadKey];
        threadDictionary[kGuestMainBundleThreadKey] = guestBundle;
        @try {
            NSBundle *observedMainBundle = NSBundle.mainBundle;
            id groupName = [observedMainBundle objectForInfoDictionaryKey:@"TWAppGroupName"];
            MGLOG(@"guest scene bundle     scoped=%@ TWAppGroupName=%@",
                  observedMainBundle.bundlePath, groupName ?: @"<absent>");
            if (![observedMainBundle.bundlePath isEqualToString:guestBundle.bundlePath] || !groupName) {
                MGLOG(@"guest scene callback   guest main bundle/config unavailable; callback not called");
                return;
            }

            MGLOG(@"guest scene callback   allocating Twitch.SceneDelegate");
            id instance = [[cls alloc] init];
            if (!instance) {
                MGLOG(@"guest scene callback   SceneDelegate init returned nil");
                return;
            }
            gGuestSceneDelegate = instance;
            if (![appDelegateBefore respondsToSelector:NSSelectorFromString(@"setUpSharePlay")]) {
                gGuestSceneDelegate = nil;
                MGLOG(@"guest scene callback   host delegate lacks SharePlay shim selector");
                return;
            }

            id<UISceneDelegate> delegate = (id<UISceneDelegate>)instance;
            MGLOG(@"guest scene handoff    UIApplication.delegate remains %@",
                  RuntimeObjectName(app.delegate));
            MGLOG(@"guest scene callback   calling willConnect");
            threadDictionary[kGuestSharePlaySkipThreadKey] = @YES;
            [delegate scene:scene willConnectToSession:session options:options];
            MGLOG(@"guest scene callback   willConnect returned");
            connected = YES;

            id appDelegateAfter = app.delegate;
            id sceneDelegateAfter = scene.delegate;
            MGLOG(@"guest scene returned   sceneDelegate=%@", RuntimeObjectName(instance));
            MGLOG(@"guest scene after      appDelegate=%@ unchanged=%@ sceneDelegate=%@ unchanged=%@ windows=%lu sceneWindows=%lu state=%ld",
                  RuntimeObjectName(appDelegateAfter), appDelegateAfter == appDelegateBefore ? @"yes" : @"NO",
                  RuntimeObjectName(sceneDelegateAfter), sceneDelegateAfter == sceneDelegateBefore ? @"yes" : @"NO",
                  (unsigned long)app.windows.count, (unsigned long)windowScene.windows.count,
                  (long)app.applicationState);
            for (UIWindow *w in windowScene.windows) {
                MGLOG(@"scene window           class=%@ key=%@ hidden=%@ root=%@",
                      RuntimeObjectName(w), w.isKeyWindow ? @"yes" : @"no",
                      w.hidden ? @"yes" : @"no", RuntimeObjectName(w.rootViewController));
            }
        } @catch (NSException *e) {
            gGuestSceneDelegate = nil;
            MGLOG(@"guest scene callback   raised %@: %@", e.name, e.reason);
        } @finally {
            if (scene.delegate != sceneDelegateBefore) scene.delegate = sceneDelegateBefore;
            MGLOG(@"host scene delegate restored %@ expected=%@",
                  RuntimeObjectName(scene.delegate), RuntimeObjectName(sceneDelegateBefore));
            if (app.delegate != appDelegateBefore) app.delegate = appDelegateBefore;
            MGLOG(@"host app delegate unchanged %@ expected=%@",
                  RuntimeObjectName(app.delegate), RuntimeObjectName(appDelegateBefore));
            if (priorSharePlaySkip) threadDictionary[kGuestSharePlaySkipThreadKey] = priorSharePlaySkip;
            else [threadDictionary removeObjectForKey:kGuestSharePlaySkipThreadKey];
            if (priorScopedBundle) threadDictionary[kGuestMainBundleThreadKey] = priorScopedBundle;
            else [threadDictionary removeObjectForKey:kGuestMainBundleThreadKey];
            MGLOG(@"host main bundle restored %@", NSBundle.mainBundle.bundlePath);
        }
    };

    if (NSThread.isMainThread) connect();
    else dispatch_sync(dispatch_get_main_queue(), connect);
    if (connected) [fm removeItemAtPath:attempted error:NULL];
    return connected;
}

// Read the signed app-group entitlement and ask the sandbox for Twitch's configured group container.
// This remains a passive diagnostic before the guarded guest lifecycle callbacks below.
static void DescribeGuestAppGroup(void) {
    NSString *guestApp = [GuestRoot() stringByAppendingPathComponent:@"Twitch.app"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                          [guestApp stringByAppendingPathComponent:@"Info.plist"]];
    id groupValue = info[@"TWAppGroupName"];
    NSString *groupName = [groupValue isKindOfClass:[NSString class]] ? groupValue : nil;
    MGLOG(@"app groups entitlement %@", Entitlement(@"com.apple.security.application-groups"));
    if (!groupName.length) {
        MGLOG(@"guest app-group        TWAppGroupName absent/invalid");
        return;
    }
    @try {
        NSURL *url = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:groupName];
        MGLOG(@"guest app-group        %@ container=%@", groupName, url.path ?: @"<nil>");
    } @catch (NSException *e) {
        MGLOG(@"guest app-group        %@ lookup raised %@: %@", groupName, e.name, e.reason);
    }
}

// --------------------------------------------------------------------------- //
// the one real experiment
// --------------------------------------------------------------------------- //

static void AttemptLoad(void) {
    NSString *exe = GuestExec();
    MGLOG(@"--- LOAD ---");
    MGLOG(@"dlopen mode           RTLD_LAZY | RTLD_LOCAL");
    MGLOG(@"guest                 %@", exe);
    MGLOG(@"header                %@", DescribeMachO(exe));
    MGLOG(@"signature             %@", DescribeSignature(exe));

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
        h = dlopen(exe.fileSystemRepresentation, RTLD_LAZY | RTLD_LOCAL);
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
    MGLOG(@"guest class TWAppDelegate %@", DescribeRuntimeClass(@"TWAppDelegate"));
    MGLOG(@"guest class Twitch.SceneDelegate %@", DescribeRuntimeClass(@"Twitch.SceneDelegate"));
    MGLOG(@"guest class Swift SceneDelegate %@", DescribeRuntimeClass(@"_TtC6Twitch13SceneDelegate"));
    MGLOG(@"guest class RCTAppDependencyProvider %@", DescribeRuntimeClass(@"RCTAppDependencyProvider"));
    DescribeGuestAppGroup();
 
    // Keep the diagnostic first. Then exercise the existing guest lifecycle callbacks with fresh
    // r13 sentinels; never call the executable entry point or UIApplicationMain.
    MGLOG(@"guest lifecycle callbacks starting");
    BOOL launched = AttemptGuestAppDelegateLaunch();
    MGLOG(@"guest launch callback  %@", launched ? @"returned successfully" : @"not completed");
    if (launched) {
        BOOL connected = AttemptGuestSceneConnect();
        MGLOG(@"guest scene callback   %@", connected ? @"returned successfully" : @"not completed/skipped");
    }
    MGLOG(@"guest lifecycle callbacks finished");
}

// One automatic probe, guarded by a sentinel so a guest that crashes the process can only do it
// once. The sentinel lives in Documents because the container survives launches, not installs.
static void MGAutoProbe(void) {
    // Round 13 disables automatic probing. The round-12 probe and manual LOAD could overlap; make
    // LOAD the only trigger and keep this function as a documented no-op for compatibility.
    MGLOG(@"auto probe            disabled in round 13; tap LOAD for one controlled attempt");
    return;
    if (![fm fileExistsAtPath:GuestExec()]) {
        gLastLoad = @"guest absent";
        MGLOG(@"auto probe            guest absent, nothing to load");
        return;
    }

    [@"round-12 guest scene probe in progress\n" writeToFile:sentinel atomically:YES
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
    if (gLoadInProgress) {
        self.status.text = @"load already in progress; wait for it to finish";
        return;
    }
    gLoadInProgress = YES;
    self.status.text = @"loading, this can take a few seconds ...";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        AttemptLoad();
        MGFlush();
        gLoadInProgress = NO;
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

    // Preserve the previous run's log across launches so a crash run is not overwritten.
    if ([[NSFileManager defaultManager] fileExistsAtPath:gLogPath]) {
        NSString *previous = [[gLogPath stringByDeletingLastPathComponent]
                              stringByAppendingPathComponent:@"mgloader.previous.txt"];
        [[NSFileManager defaultManager] removeItemAtPath:previous error:NULL];
        [[NSFileManager defaultManager] copyItemAtPath:gLogPath toPath:previous error:NULL];
    }
    MGLOG(@"MGLoader %s  %@ %@", kRound, @__DATE__, @__TIME__);
    BOOL sceneCaptureReady = MGInstallHostSceneOptionsCapture();
    MGLOG(@"host scene options hook %@", sceneCaptureReady ? @"installed" : @"not installed (scene callback unavailable)");
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
    MGLOG(@"guest mode            %@", GuestMode());
    MGLOG(@"guest roots           %@", GuestRoots());
    MGLOG(@"guest header          %@", DescribeMachO(GuestExec()));
    MGLOG(@"guest signature       %@", DescribeSignature(GuestExec()));
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

    MGFlush(); // auto probe disabled in round 13
}
