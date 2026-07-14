import com.android.bundle.Config
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Locale
import java.util.jar.JarFile
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

private val ELF64_HEADER_SIZE = 64
private val ELF64_PROGRAM_HEADER_SIZE = 56
private val ELF64_SECTION_HEADER_SIZE = 64
private val ELF64_DYNAMIC_ENTRY_SIZE = 16L
private val ET_DYN = 3
private val PT_LOAD = 1L
private val PT_DYNAMIC = 2L
private val PT_GNU_STACK = 0x6474e551L
private val PT_GNU_RELRO = 0x6474e552L
private val PF_X = 1L
private val SHT_SYMTAB = 2L
private val SHT_NOBITS = 8L
private val NT_GNU_BUILD_ID = 3L
private val DT_NULL = 0L
private val DT_TEXTREL = 22L
private val DT_FLAGS = 30L
private val DT_FLAGS_1 = 0x6fff_fffbL
private val DF_TEXTREL = 0x4L
private val DF_BIND_NOW = 0x8L
private val DF_1_NOW = 0x1L
private val REQUIRED_NATIVE_ALIGNMENT = 16L * 1024L
private val MAX_BUNDLE_ENTRY_SIZE = 256L * 1024L * 1024L
private val REQUIRED_NATIVE_LIBRARIES = setOf(
    "base/lib/arm64-v8a/libhns_dane_browser_ffi.so",
    "base/lib/x86_64/libhns_dane_browser_ffi.so",
)

private data class ElfSection(
    val name: String,
    val type: Long,
    val offset: Long,
    val size: Long,
)

private data class ElfInspection(
    val buildId: ByteArray,
    val sectionNames: Set<String>,
    val hasStaticSymbolTable: Boolean,
)

private data class DynamicHardening(
    val hasTextRelocations: Boolean,
    val hasImmediateBinding: Boolean,
)

private fun readBundleEntry(zip: ZipFile, entry: ZipEntry): ByteArray {
    check(entry.size in 0..MAX_BUNDLE_ENTRY_SIZE) {
        "Bundle entry ${entry.name} has an invalid or excessive uncompressed size: ${entry.size}"
    }

    return zip.getInputStream(entry).use { input ->
        val output = ByteArrayOutputStream(entry.size.toInt())
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val count = input.read(buffer)
            if (count == -1) {
                break
            }
            total += count
            check(total <= MAX_BUNDLE_ENTRY_SIZE) {
                "Bundle entry ${entry.name} exceeds the maximum inspected size."
            }
            output.write(buffer, 0, count)
        }
        output.toByteArray()
    }
}

private fun expectedElfMachine(abi: String): Int = when (abi) {
    "arm64-v8a" -> 183
    "x86_64" -> 62
    else -> error("Unsupported native ABI in release bundle: $abi")
}

private fun readGnuBuildId(name: String, bytes: ByteArray, section: ElfSection): ByteArray {
    val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    val sectionEnd = section.offset + section.size
    var cursor = section.offset
    val buildIds = mutableListOf<ByteArray>()
    while (cursor + 12L <= sectionEnd) {
        val header = cursor.toInt()
        val noteNameSize = elf.getInt(header).toLong() and 0xffff_ffffL
        val descriptorSize = elf.getInt(header + 4).toLong() and 0xffff_ffffL
        val noteType = elf.getInt(header + 8).toLong() and 0xffff_ffffL
        val noteNameStart = cursor + 12L
        val noteNameEnd = noteNameStart + noteNameSize
        val descriptorStart = (noteNameEnd + 3L) and -4L
        val descriptorEnd = descriptorStart + descriptorSize
        check(
            noteNameEnd >= noteNameStart &&
                descriptorStart >= noteNameEnd &&
                descriptorEnd >= descriptorStart &&
                descriptorEnd <= sectionEnd,
        ) { "$name has malformed note data in ${section.name}." }

        val isGnuBuildId = noteType == NT_GNU_BUILD_ID &&
            noteNameSize >= 3L &&
            bytes[noteNameStart.toInt()] == 'G'.code.toByte() &&
            bytes[noteNameStart.toInt() + 1] == 'N'.code.toByte() &&
            bytes[noteNameStart.toInt() + 2] == 'U'.code.toByte()
        if (isGnuBuildId) {
            buildIds += bytes.copyOfRange(descriptorStart.toInt(), descriptorEnd.toInt())
        }
        cursor = (descriptorEnd + 3L) and -4L
    }

    check(buildIds.size == 1) { "$name must contain exactly one GNU Build ID." }
    check(buildIds.single().size == 20) { "$name must use a 20-byte SHA-1 GNU Build ID." }
    return buildIds.single()
}

private fun inspectElf(name: String, bytes: ByteArray, expectedMachine: Int): ElfInspection {
    check(bytes.size >= ELF64_HEADER_SIZE) { "$name is too small to be an ELF64 file." }
    check(
        bytes[0] == 0x7f.toByte() &&
            bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() &&
            bytes[3] == 'F'.code.toByte(),
    ) { "$name does not have an ELF header." }
    check(bytes[4].toInt() == 2) { "$name is not an ELF64 file." }
    check(bytes[5].toInt() == 1) { "$name is not a little-endian ELF file." }
    check(bytes[6].toInt() == 1) { "$name has an unsupported ELF version." }

    val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    val type = elf.getShort(16).toInt() and 0xffff
    val machine = elf.getShort(18).toInt() and 0xffff
    check(type == ET_DYN) { "$name is not an ET_DYN shared object." }
    check(machine == expectedMachine) {
        "$name has ELF machine $machine; expected $expectedMachine."
    }

    val sectionHeaderOffset = elf.getLong(40)
    val sectionHeaderEntrySize = elf.getShort(58).toInt() and 0xffff
    val sectionHeaderCount = elf.getShort(60).toInt() and 0xffff
    val sectionNameTableIndex = elf.getShort(62).toInt() and 0xffff
    check(sectionHeaderOffset >= 0L) { "$name has a negative section-header offset." }
    check(sectionHeaderEntrySize >= ELF64_SECTION_HEADER_SIZE) {
        "$name has an undersized ELF64 section-header entry: $sectionHeaderEntrySize"
    }
    check(sectionHeaderCount > 0) { "$name has no section headers." }
    check(sectionNameTableIndex in 1 until sectionHeaderCount) {
        "$name has an invalid section-name string-table index."
    }
    val sectionHeaderTableSize = sectionHeaderEntrySize.toLong() * sectionHeaderCount.toLong()
    check(sectionHeaderTableSize <= bytes.size.toLong()) {
        "$name has an out-of-bounds section-header table."
    }
    check(sectionHeaderOffset <= bytes.size.toLong() - sectionHeaderTableSize) {
        "$name has an out-of-bounds section-header table."
    }

    fun sectionHeader(index: Int): Int =
        (sectionHeaderOffset + index.toLong() * sectionHeaderEntrySize.toLong()).toInt()

    val sectionNameTableHeader = sectionHeader(sectionNameTableIndex)
    val sectionNameTableOffset = elf.getLong(sectionNameTableHeader + 24)
    val sectionNameTableSize = elf.getLong(sectionNameTableHeader + 32)
    check(sectionNameTableOffset >= 0L && sectionNameTableSize > 0L) {
        "$name has an invalid section-name string table."
    }
    check(
        sectionNameTableOffset <= bytes.size.toLong() &&
            sectionNameTableSize <= bytes.size.toLong() - sectionNameTableOffset,
    ) { "$name has an out-of-bounds section-name string table." }

    val sectionNameTableEnd = (sectionNameTableOffset + sectionNameTableSize).toInt()
    val sections = (0 until sectionHeaderCount).map { index ->
        val header = sectionHeader(index)
        val nameOffset = elf.getInt(header).toLong() and 0xffff_ffffL
        check(nameOffset < sectionNameTableSize) {
            "$name section $index has an out-of-bounds name."
        }
        val nameStart = (sectionNameTableOffset + nameOffset).toInt()
        var nameEnd = nameStart
        while (nameEnd < sectionNameTableEnd && bytes[nameEnd] != 0.toByte()) {
            nameEnd += 1
        }
        check(nameEnd < sectionNameTableEnd) { "$name section $index has an unterminated name." }

        val sectionType = elf.getInt(header + 4).toLong() and 0xffff_ffffL
        val sectionOffset = elf.getLong(header + 24)
        val sectionSize = elf.getLong(header + 32)
        check(sectionOffset >= 0L && sectionSize >= 0L) {
            "$name section $index has negative bounds."
        }
        check(
            sectionOffset <= bytes.size.toLong() &&
                (sectionType == SHT_NOBITS || sectionSize <= bytes.size.toLong() - sectionOffset),
        ) {
            "$name section $index is out of bounds."
        }
        ElfSection(
            name = String(bytes, nameStart, nameEnd - nameStart, Charsets.US_ASCII),
            type = sectionType,
            offset = sectionOffset,
            size = sectionSize,
        )
    }
    val buildIdSection = sections.singleOrNull { section -> section.name == ".note.gnu.build-id" }
    checkNotNull(buildIdSection) { "$name does not contain a .note.gnu.build-id section." }

    return ElfInspection(
        buildId = readGnuBuildId(name, bytes, buildIdSection),
        sectionNames = sections.map(ElfSection::name).toSet(),
        hasStaticSymbolTable = sections.any { section -> section.type == SHT_SYMTAB },
    )
}

private fun requireNoLocalPaths(name: String, bytes: ByteArray, forbiddenPathPrefixes: List<String>) {
    val binaryText = bytes.toString(Charsets.ISO_8859_1)
    forbiddenPathPrefixes.forEach { prefix ->
        check(!binaryText.contains(prefix)) { "$name contains a local build path beginning with $prefix." }
    }
}

private fun inspectDynamicHardening(
    name: String,
    elf: ByteBuffer,
    fileLength: Long,
    programHeaderIndex: Int,
    fileOffset: Long,
    fileSize: Long,
): DynamicHardening {
    check(fileOffset >= 0L && fileSize > 0L) {
        "$name has invalid PT_DYNAMIC bounds in program header $programHeaderIndex."
    }
    check(fileSize % ELF64_DYNAMIC_ENTRY_SIZE == 0L) {
        "$name PT_DYNAMIC size is not a multiple of the ELF64 dynamic-entry size."
    }
    check(fileOffset <= fileLength && fileSize <= fileLength - fileOffset) {
        "$name has an out-of-bounds PT_DYNAMIC segment."
    }

    var hasTerminator = false
    var hasTextRelocations = false
    var hasImmediateBinding = false
    val dynamicEntryCount = fileSize / ELF64_DYNAMIC_ENTRY_SIZE
    for (index in 0 until dynamicEntryCount.toInt()) {
        val entryOffset = fileOffset + index.toLong() * ELF64_DYNAMIC_ENTRY_SIZE
        val entry = entryOffset.toInt()
        val tag = elf.getLong(entry)
        val value = elf.getLong(entry + 8)
        if (tag == DT_NULL) {
            hasTerminator = true
            break
        }
        when (tag) {
            DT_TEXTREL -> hasTextRelocations = true
            DT_FLAGS -> {
                hasTextRelocations = hasTextRelocations || (value and DF_TEXTREL) != 0L
                hasImmediateBinding = hasImmediateBinding || (value and DF_BIND_NOW) != 0L
            }
            DT_FLAGS_1 -> {
                hasImmediateBinding = hasImmediateBinding || (value and DF_1_NOW) != 0L
            }
        }
    }
    check(hasTerminator) { "$name PT_DYNAMIC segment is not DT_NULL-terminated." }
    return DynamicHardening(hasTextRelocations, hasImmediateBinding)
}

private fun require16KiBElf(
    name: String,
    bytes: ByteArray,
    forbiddenPathPrefixes: List<String>,
): ElfInspection {
    val abi = name.removePrefix("base/lib/").substringBefore('/')
    val inspection = inspectElf(name, bytes, expectedElfMachine(abi))
    val elf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    val programHeaderOffset = elf.getLong(32)
    val programHeaderEntrySize = elf.getShort(54).toInt() and 0xffff
    val programHeaderCount = elf.getShort(56).toInt() and 0xffff
    check(programHeaderOffset >= 0L) { "$name has a negative program-header offset." }
    check(programHeaderEntrySize >= ELF64_PROGRAM_HEADER_SIZE) {
        "$name has an undersized ELF64 program-header entry: $programHeaderEntrySize"
    }
    check(programHeaderCount > 0) { "$name has no program headers." }

    val programHeaderTableSize = programHeaderEntrySize.toLong() * programHeaderCount.toLong()
    check(programHeaderTableSize <= bytes.size.toLong()) {
        "$name has an out-of-bounds program-header table."
    }
    check(programHeaderOffset <= bytes.size.toLong() - programHeaderTableSize) {
        "$name has an out-of-bounds program-header table."
    }

    var loadSegmentCount = 0
    var hasGnuRelro = false
    var gnuStackCount = 0
    var hasExecutableGnuStack = false
    var dynamicSegmentCount = 0
    var hasTextRelocations = false
    var hasImmediateBinding = false
    repeat(programHeaderCount) { index ->
        val headerOffset = programHeaderOffset + index.toLong() * programHeaderEntrySize.toLong()
        val header = headerOffset.toInt()
        val type = elf.getInt(header).toLong() and 0xffff_ffffL
        val flags = elf.getInt(header + 4).toLong() and 0xffff_ffffL
        if (type == PT_GNU_RELRO) {
            hasGnuRelro = true
        }
        if (type == PT_GNU_STACK) {
            gnuStackCount += 1
            hasExecutableGnuStack = hasExecutableGnuStack || (flags and PF_X) != 0L
        }
        if (type == PT_DYNAMIC) {
            dynamicSegmentCount += 1
            val dynamicHardening = inspectDynamicHardening(
                name = name,
                elf = elf,
                fileLength = bytes.size.toLong(),
                programHeaderIndex = index,
                fileOffset = elf.getLong(header + 8),
                fileSize = elf.getLong(header + 32),
            )
            hasTextRelocations = hasTextRelocations || dynamicHardening.hasTextRelocations
            hasImmediateBinding = hasImmediateBinding || dynamicHardening.hasImmediateBinding
        }
        if (type != PT_LOAD) {
            return@repeat
        }

        loadSegmentCount += 1
        val fileOffset = elf.getLong(header + 8)
        val virtualAddress = elf.getLong(header + 16)
        val fileSize = elf.getLong(header + 32)
        val memorySize = elf.getLong(header + 40)
        val alignment = elf.getLong(header + 48)

        check(fileOffset >= 0L && virtualAddress >= 0L && fileSize >= 0L && memorySize >= 0L) {
            "$name has negative values in PT_LOAD segment $index."
        }
        check(memorySize >= fileSize) {
            "$name has a PT_LOAD segment whose memory size is smaller than its file size."
        }
        check(fileOffset <= bytes.size.toLong() && fileSize <= bytes.size.toLong() - fileOffset) {
            "$name has an out-of-bounds PT_LOAD segment."
        }
        check(alignment >= REQUIRED_NATIVE_ALIGNMENT && (alignment and (alignment - 1L)) == 0L) {
            "$name PT_LOAD segment $index alignment is $alignment; at least 16384 and a power of two are required."
        }
        check(fileOffset % alignment == virtualAddress % alignment) {
            "$name PT_LOAD segment $index has incongruent file and virtual-address alignment."
        }
    }

    check(loadSegmentCount > 0) { "$name has no PT_LOAD segments." }
    check(hasGnuRelro) { "$name does not contain a GNU_RELRO program header." }
    check(gnuStackCount == 1) { "$name must contain exactly one PT_GNU_STACK program header." }
    check(!hasExecutableGnuStack) { "$name requests an executable GNU stack." }
    check(dynamicSegmentCount == 1) { "$name must contain exactly one PT_DYNAMIC program header." }
    check(!hasTextRelocations) { "$name enables or declares text relocations." }
    check(hasImmediateBinding) { "$name does not enable immediate binding via DF_BIND_NOW or DF_1_NOW." }
    val debugSections = inspection.sectionNames.filter { section ->
        section == ".debug" || section.startsWith(".debug_") || section.startsWith(".zdebug_")
    }
    check(debugSections.isEmpty()) { "$name still contains debug sections: $debugSections" }
    check(!inspection.hasStaticSymbolTable) { "$name still contains a static symbol table." }
    requireNoLocalPaths(name, bytes, forbiddenPathPrefixes)
    return inspection
}

private fun requireNativeDebugMetadata(
    name: String,
    bytes: ByteArray,
    expectedMachine: Int,
    expectedBuildId: ByteArray,
    forbiddenPathPrefixes: List<String>,
) {
    val inspection = inspectElf(name, bytes, expectedMachine)
    check(inspection.buildId.contentEquals(expectedBuildId)) {
        "$name GNU Build ID does not match its packaged native library."
    }
    check(inspection.hasStaticSymbolTable) { "$name does not contain a static symbol table." }
    check(
        inspection.sectionNames.any { section ->
            section == ".debug" || section.startsWith(".debug_") || section.startsWith(".zdebug_")
        },
    ) { "$name does not contain debug sections." }
    requireNoLocalPaths(name, bytes, forbiddenPathPrefixes)
}

private fun requireExpectedNativeLibraries(nativeLibraries: List<String>) {
    check(
        nativeLibraries.size == REQUIRED_NATIVE_LIBRARIES.size &&
            nativeLibraries.toSet() == REQUIRED_NATIVE_LIBRARIES,
    ) {
        "Release app bundle native libraries must be exactly $REQUIRED_NATIVE_LIBRARIES. " +
            "Found: $nativeLibraries"
    }
}

private fun verifyReleaseBundleStructure(bundle: java.io.File, forbiddenPathPrefixes: List<String>) {
    check(bundle.isFile) { "Release app bundle was not found at ${bundle.absolutePath}" }

    ZipFile(bundle).use { zip ->
        val bundleConfigEntry = checkNotNull(zip.getEntry("BundleConfig.pb")) {
            "Release app bundle does not contain BundleConfig.pb."
        }
        val bundleConfig = zip.getInputStream(bundleConfigEntry).use(Config.BundleConfig::parseFrom)
        check(bundleConfig.hasOptimizations()) {
            "BundleConfig.pb does not contain optimization settings."
        }
        val optimizations = bundleConfig.optimizations
        check(optimizations.hasUncompressNativeLibraries()) {
            "BundleConfig.pb does not configure uncompressed native libraries."
        }
        val uncompressNativeLibraries = optimizations.uncompressNativeLibraries
        check(uncompressNativeLibraries.enabled) {
            "BundleConfig.pb does not enable uncompressed native libraries."
        }
        check(
            uncompressNativeLibraries.alignment ==
                Config.UncompressNativeLibraries.PageAlignment.PAGE_ALIGNMENT_16K,
        ) {
            "BundleConfig.pb native-library alignment is ${uncompressNativeLibraries.alignment}; " +
                "PAGE_ALIGNMENT_16K is required."
        }

        val thirdPartyNoticesEntry = checkNotNull(zip.getEntry("base/assets/third_party_notices.txt")) {
            "Release app bundle does not contain base/assets/third_party_notices.txt."
        }
        check(!thirdPartyNoticesEntry.isDirectory) {
            "Release app bundle third-party notices entry is not a file."
        }
        check(readBundleEntry(zip, thirdPartyNoticesEntry).toString(Charsets.UTF_8).isNotBlank()) {
            "Release app bundle third-party notices file is empty."
        }

        val proguardMappingEntry = checkNotNull(
            zip.getEntry("BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map"),
        ) {
            "Release app bundle does not contain the R8 deobfuscation mapping."
        }
        check(!proguardMappingEntry.isDirectory && readBundleEntry(zip, proguardMappingEntry).isNotEmpty()) {
            "Release app bundle R8 deobfuscation mapping is empty or not a file."
        }

        val nativeLibraryEntries = zip.entries().asSequence()
            .filterNot(ZipEntry::isDirectory)
            .filter { entry -> entry.name.startsWith("base/lib/") && entry.name.endsWith(".so") }
            .sortedBy(ZipEntry::getName)
            .toList()
        val nativeLibraries = nativeLibraryEntries.map(ZipEntry::getName)
        val allowedAbis = setOf("arm64-v8a", "x86_64")
        val bundledAbis = nativeLibraries
            .map { name -> name.removePrefix("base/lib/").substringBefore('/') }
            .toSet()
        check(bundledAbis == allowedAbis) {
            "Release app bundle native-library ABIs must be exactly $allowedAbis. Found: $bundledAbis"
        }
        requireExpectedNativeLibraries(nativeLibraries)
        nativeLibraryEntries.forEach { entry ->
            val relativeNativePath = entry.name.removePrefix("base/lib/")
            val abi = relativeNativePath.substringBefore('/')
            val inspection = require16KiBElf(
                entry.name,
                readBundleEntry(zip, entry),
                forbiddenPathPrefixes,
            )
            val debugMetadataName =
                "BUNDLE-METADATA/com.android.tools.build.debugsymbols/$relativeNativePath.dbg"
            val debugMetadataEntry = checkNotNull(zip.getEntry(debugMetadataName)) {
                "Release app bundle does not contain full native debug metadata for ${entry.name}."
            }
            requireNativeDebugMetadata(
                debugMetadataName,
                readBundleEntry(zip, debugMetadataEntry),
                expectedElfMachine(abi),
                inspection.buildId,
                forbiddenPathPrefixes,
            )
        }
    }
}

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
    environment("HNS_RUST_ANDROID_PROFILE", "release")

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
    inputs.property("rustAndroidProfile", "release")
    inputs.property("cargoNdkVersion", System.getenv("HNS_CARGO_NDK_VERSION") ?: "4.1.2")
    inputs.property(
        "androidNdkVersion",
        System.getenv("HNS_ANDROID_NDK_VERSION") ?: "28.2.13676358",
    )
    inputs.property("androidNdkHome", androidNdkHome)
    if (androidNdkHome.isNotBlank()) {
        inputs.file(file(androidNdkHome).resolve("source.properties")).optional()
    }
    outputs.dir(rustJniLibsDir)
}

android {
    namespace = "com.denuoweb.hnsdane"
    compileSdk = 37
    if (androidNdkHome.isNotBlank()) {
        ndkPath = androidNdkHome
    }

    defaultConfig {
        applicationId = "com.denuoweb.hnsdane"
        minSdk = 34
        targetSdk = 37
        versionCode = 35
        versionName = "0.3.14"

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

tasks.register("verifyReleaseBundleStructure") {
    group = "verification"
    description = "Builds the release AAB and verifies its native-library and 16 KiB page-size structure."
    dependsOn("bundleRelease")

    doLast {
        val bundle = layout.buildDirectory.file("outputs/bundle/release/app-release.aab").get().asFile
        val repositoryRoot = rootProject.layout.projectDirectory.asFile.parentFile.absolutePath
        val forbiddenPathPrefixes = listOfNotNull(
            repositoryRoot,
            System.getenv("HOME"),
            System.getenv("CARGO_HOME"),
            System.getenv("RUSTUP_HOME"),
            androidNdkHome,
        ).filter { prefix -> prefix.length > 1 }.distinct()
        verifyReleaseBundleStructure(bundle, forbiddenPathPrefixes)
    }
}

tasks.register("verifyPlayReleaseBundle") {
    group = "verification"
    description = "Builds the release AAB and fails if it is not signed for Google Play upload."
    dependsOn("verifyReleaseBundleStructure")

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
