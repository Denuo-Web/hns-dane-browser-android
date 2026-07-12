import java.security.MessageDigest
import java.util.Locale
import java.util.jar.JarFile
import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.android.application)
}

val playUploadStoreFile = providers.environmentVariable("HNS_DANE_BROWSER_UPLOAD_STORE_FILE").orNull
val playUploadStorePassword = providers.environmentVariable("HNS_DANE_BROWSER_UPLOAD_STORE_PASSWORD").orNull
val playUploadKeyAlias = providers.environmentVariable("HNS_DANE_BROWSER_UPLOAD_KEY_ALIAS").orNull
val playUploadKeyPassword = providers.environmentVariable("HNS_DANE_BROWSER_UPLOAD_KEY_PASSWORD").orNull
val playUploadCertificateSha256 = providers.environmentVariable(
    "HNS_DANE_BROWSER_UPLOAD_CERTIFICATE_SHA256",
).orNull
val playSigningConfigured = listOf(
    playUploadStoreFile,
    playUploadStorePassword,
    playUploadKeyAlias,
    playUploadKeyPassword,
).all { !it.isNullOrBlank() }

val rustJniLibsDir = layout.buildDirectory.dir("generated/rustJniLibs")
val rustJniLibsDirFile = rustJniLibsDir.get().asFile
val androidNdkHome = System.getenv("ANDROID_NDK_HOME") ?: System.getenv("ANDROID_NDK_ROOT") ?: ""
val buildRustAndroid = tasks.register<Exec>("buildRustAndroid") {
    val rootDir = rootProject.layout.projectDirectory.asFile.parentFile
    val script = rootDir.resolve("scripts/build-rust-android.sh")

    workingDir = rootDir
    commandLine("bash", script.absolutePath, rustJniLibsDirFile.absolutePath)

    environment("ANDROID_NDK_HOME", androidNdkHome)
    environment("ANDROID_NDK_ROOT", androidNdkHome)

    inputs.files(
        script,
        fileTree(rootDir.resolve("rust/crates")) {
            include("**/*.rs")
            include("**/*.toml")
            include("**/*.txt")
        },
        rootDir.resolve("rust/Cargo.toml"),
        rootDir.resolve("rust/Cargo.lock"),
        rootDir.resolve("rust/rust-toolchain.toml"),
    )
    inputs.property("rustAndroidProfile", System.getenv("HNS_RUST_ANDROID_PROFILE") ?: "release")
    inputs.property("cargoNdkVersion", System.getenv("HNS_CARGO_NDK_VERSION") ?: "4.1.2")
    inputs.property("androidNdkVersion", System.getenv("HNS_ANDROID_NDK_VERSION") ?: "")
    inputs.property("androidNdkHome", androidNdkHome)
    if (androidNdkHome.isNotBlank()) {
        inputs.file(file(androidNdkHome).resolve("source.properties")).optional()
    }
    outputs.dir(rustJniLibsDir)
}

android {
    namespace = "com.denuoweb.hnsdane"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.denuoweb.hnsdane"
        minSdk = 34
        targetSdk = 37
        versionCode = 29
        versionName = "0.3.8"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (playSigningConfigured) {
            create("playUpload") {
                storeFile = file(playUploadStoreFile!!)
                storePassword = playUploadStorePassword
                keyAlias = playUploadKeyAlias
                keyPassword = playUploadKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            if (playSigningConfigured) {
                signingConfig = signingConfigs.getByName("playUpload")
            }
            ndk {
                debugSymbolLevel = "FULL"
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        buildConfig = true
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(rustJniLibsDirFile.absolutePath)
        }
    }
}

tasks.named("preBuild") {
    dependsOn(buildRustAndroid)
}

tasks.register("verifyPlayReleaseBundle") {
    group = "verification"
    description = "Builds the release AAB and fails if it is not signed for Google Play upload."
    dependsOn("bundleRelease")

    doLast {
        check(playSigningConfigured) {
            "Play upload signing is not configured. Set HNS_DANE_BROWSER_UPLOAD_STORE_FILE, " +
                "HNS_DANE_BROWSER_UPLOAD_STORE_PASSWORD, HNS_DANE_BROWSER_UPLOAD_KEY_ALIAS, and " +
                "HNS_DANE_BROWSER_UPLOAD_KEY_PASSWORD before uploading to Play Console."
        }

        val bundle = layout.buildDirectory.file("outputs/bundle/release/app-release.aab").get().asFile
        check(bundle.isFile) { "Release app bundle was not found at ${bundle.absolutePath}" }

        val normalizedExpectedSignerSha256 = playUploadCertificateSha256
            ?.trim()
            ?.replace(Regex("^sha-?256\\s*:\\s*", RegexOption.IGNORE_CASE), "")
            ?.filterNot { character -> character == ':' || character.isWhitespace() }
            ?.lowercase()
        val expectedSignerSha256 = checkNotNull(
            normalizedExpectedSignerSha256?.takeIf { fingerprint ->
                fingerprint.matches(Regex("[0-9a-f]{64}"))
            },
        ) {
            "Set HNS_DANE_BROWSER_UPLOAD_CERTIFICATE_SHA256 to the 64-hex-character SHA-256 " +
                "fingerprint of the expected Play upload signing certificate."
        }

        var verifiedContentEntries = 0
        JarFile(bundle, true).use { jar ->
            val readBuffer = ByteArray(DEFAULT_BUFFER_SIZE)
            jar.entries().asSequence()
                .filterNot { entry ->
                    val name = entry.name.uppercase(Locale.ROOT)
                    val signatureMetadata = name == "META-INF/MANIFEST.MF" ||
                        (name.startsWith("META-INF/") && (
                            name.endsWith(".SF") ||
                                name.endsWith(".RSA") ||
                                name.endsWith(".DSA") ||
                                name.endsWith(".EC") ||
                                name.substringAfterLast('/').startsWith("SIG-")
                            ))
                    entry.isDirectory || signatureMetadata
                }
                .forEach { entry ->
                    jar.getInputStream(entry).use { input ->
                        while (input.read(readBuffer) != -1) {
                            // Reading every byte makes JarFile verify the entry digest and signature.
                        }
                    }

                    val signerFingerprints = entry.codeSigners
                        ?.map { signer ->
                            val signerCertificate = signer.signerCertPath.certificates.first()
                            MessageDigest.getInstance("SHA-256")
                                .digest(signerCertificate.encoded)
                                .joinToString(separator = "") { byte ->
                                    "%02x".format(byte.toInt() and 0xff)
                                }
                        }
                        ?.toSet()
                        .orEmpty()
                    check(signerFingerprints == setOf(expectedSignerSha256)) {
                        "Release bundle entry ${entry.name} is unsigned, signed by an unexpected " +
                            "certificate, or has mixed signers: $signerFingerprints"
                    }
                    verifiedContentEntries += 1
                }
        }
        check(verifiedContentEntries > 0) { "Release app bundle contains no signed content entries." }

        val nativeLibraries = ZipFile(bundle).use { zip ->
            zip.entries().asSequence()
                .map { it.name }
                .filter { it.endsWith(".so") }
                .sorted()
                .toList()
        }
        val requiredLibraries = setOf(
            "base/lib/arm64-v8a/libhns_dane_browser_ffi.so",
            "base/lib/x86_64/libhns_dane_browser_ffi.so",
        )
        check(nativeLibraries.containsAll(requiredLibraries)) {
            "Release app bundle is missing required 64-bit native libraries. Found: $nativeLibraries"
        }
    }
}

dependencies {
    implementation(libs.androidx.activity)
    implementation(libs.androidx.core)
    implementation(libs.androidx.webkit)

    testImplementation(libs.junit)
    testImplementation(libs.json)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
