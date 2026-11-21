package dev.sshsync.sshsync

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// FlutterFragmentActivity is required by the biometric prompt.
class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "sshsync/platform")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    // Blocks screenshots and blanks the app in the recents view.
                    "setSecure" -> {
                        if (call.arguments as Boolean) {
                            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        } else {
                            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        }
                        result.success(null)
                    }
                    // Copies text flagged as sensitive so Android 13+ does not
                    // show it in the clipboard preview.
                    "copySensitive" -> {
                        val clip = ClipData.newPlainText("secret", call.arguments as String)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            clip.description.extras = PersistableBundle().apply {
                                putBoolean(
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                                        ClipDescription.EXTRA_IS_SENSITIVE
                                    else "android.content.extra.IS_SENSITIVE",
                                    true
                                )
                            }
                        }
                        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                            .setPrimaryClip(clip)
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }
}
