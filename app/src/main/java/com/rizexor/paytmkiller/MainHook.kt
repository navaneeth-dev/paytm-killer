package com.rizexor.paytmkiller

import android.content.Context
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.callbacks.XC_LoadPackage
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.XC_MethodHook.MethodHookParam
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import java.security.cert.X509Certificate

class MainHook : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedBridge.log("PayTM Killer Loaded!")

        // Filtering unnecessary applications
        if (lpparam.packageName != "net.one97.paytm") return
        // Execute Hook
        hook(lpparam)
    }

    private fun hook(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            "com.paytm.network.CJRCommonNetworkCall",
            lpparam.classLoader,
            "addIntegrityHeaders",
            Map::class.java,
            String::class.java,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    XposedBridge.log("[+] addIntegrityHeaders called")
                    XposedHelpers.callMethod(param.args[0], "remove", "x-int-token")
                }
            })

        XposedHelpers.findAndHookMethod(
            "net.one97.paytm.utils.c",
            lpparam.classLoader,
            "B",
            Context::class.java,
            object : XC_MethodReplacement() {
                override fun replaceHookedMethod(param: MethodHookParam): Any {
                    XposedBridge.log("[+] UserAgent called")
                    val userAgentStr = XposedHelpers.newInstance(
                        XposedHelpers.findClass("java.lang.String", lpparam.classLoader),
                        "Paytm"
                    )
                    return userAgentStr;
                }
            })


        // Hook CronetEngine$Builder.addPublicKeyPins
        val builderClass =
            XposedHelpers.findClass("org.chromium.net.CronetEngine\$Builder", lpparam.classLoader)
        XposedHelpers.findAndHookMethod(
            builderClass,
            "addPublicKeyPins",
            String::class.java,
            Set::class.java,
            Boolean::class.java,
            java.util.Date::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    XposedBridge.log("[+] Hooked CronetEngine.Builder.addPublicKeyPins")
                    param.result = param.thisObject
                }
            })

//        val className = "com.android.org.conscrypt.TrustManagerImpl" // Replace with your target class
//
//        try {
//            val targetClass = XposedHelpers.findClass(className, lpparam.classLoader)
//
//            for (method in targetClass.declaredMethods) {
//                if (method.name == "checkTrustedRecursive") {
//                    XposedBridge.log("Hooking method: ${method.name} -> Params: ${method.parameterTypes.joinToString()}")
//
////                    XposedHelpers.findAndHookMethod(
////                        targetClass,
////                        method.name,
////                        *method.parameterTypes,  // Dynamically use all parameters
////                        object : XC_MethodHook() {
////                            override fun beforeHookedMethod(param: MethodHookParam) {
////                                XposedBridge.log("[+] Hooked ${method.name}")
////                                param.args.forEachIndexed { index, arg ->
////                                    XposedBridge.log("Arg[$index]: Type=${arg?.javaClass?.name}, Value=$arg")
////                                }
////                            }
////                        }
////                    )
//                }
//            }
//        } catch (e: Throwable) {
//            XposedBridge.log("[-] Failed to hook class: $e")
//        }

        // Hook TrustManagerImpl.checkTrustedRecursive
        XposedHelpers.findAndHookMethod(
            "com.android.org.conscrypt.TrustManagerImpl",
            lpparam.classLoader,
            "checkTrustedRecursive",

            Array<X509Certificate>::class.java, // X509Certificate[]
            ByteArray::class.java, // byte[] (B in reflection)
            ByteArray::class.java, // byte[] (B in reflection)
            String::class.java, // String
            Boolean::class.javaPrimitiveType, // boolean
            List::class.java, // List<X509Certificate>
            List::class.java, // List<TrustAnchor>
            Set::class.java, // Set<X509Certificate>

            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val host = param.args[3] as String
                    XposedBridge.log("[+] Bypassing TrustManagerImpl checkTrustedRecursive for: ${host}")
                    param.result = ArrayList<Any>()
                }
            })
    }
}