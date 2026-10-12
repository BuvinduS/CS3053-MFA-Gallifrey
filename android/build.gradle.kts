// Load each plugin once at the root (versions come from settings.gradle.kts)
// so :core and :app share the same Kotlin plugin instance.
plugins {
    id("com.android.application") apply false
    id("org.jetbrains.kotlin.jvm") apply false
    id("org.jetbrains.kotlin.android") apply false
    id("org.jetbrains.kotlin.plugin.compose") apply false
}
