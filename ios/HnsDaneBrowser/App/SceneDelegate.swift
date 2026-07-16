import UIKit

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var browserViewController: BrowserViewController?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene,
              let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
            return
        }

        let browser = BrowserViewController(process: appDelegate.browserProcess)
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = browser
        window.makeKeyAndVisible()
        self.window = window
        browserViewController = browser

        if let incomingURL = connectionOptions.urlContexts.first?.url {
            browser.openExternalURL(incomingURL)
        }
    }

    func sceneWillEnterForeground(_ scene: UIScene) {
        browserViewController?.resumeBrowsing()
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        browserViewController?.suspendBrowsing()
    }

    func scene(
        _ scene: UIScene,
        openURLContexts URLContexts: Set<UIOpenURLContext>
    ) {
        guard let url = URLContexts.first?.url else { return }
        browserViewController?.openExternalURL(url)
    }

    func sceneDidDisconnect(_ scene: UIScene) {
        browserViewController?.destroyBrowsing()
        browserViewController = nil
    }
}
