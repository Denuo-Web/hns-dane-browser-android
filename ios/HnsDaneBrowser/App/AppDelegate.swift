import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    let browserProcess = BrowserProcess()

    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(
            name: "Browser",
            sessionRole: connectingSceneSession.role
        )
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }

    func applicationWillTerminate(_ application: UIApplication) {
        browserProcess.close()
    }
}
