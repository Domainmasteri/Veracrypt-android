#include <jni.h>
#include <string>
#include <android/log.h>

#define LOG_TAG "VeraCrypt-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" {

/**
 * Returns the native library version string.
 * Called from NativeBridge.kt via System.loadLibrary("veracrypt-native").
 */
JNIEXPORT jstring JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeGetVersion(
        JNIEnv *env,
        jclass /* clazz */) {
    return env->NewStringUTF("0.1.0-stub");
}

/**
 * Stub: attempt to parse the VeraCrypt volume header from a byte buffer.
 *
 * @param headerBytes  First 512 bytes of the container file (the encrypted header sector).
 * @param password     UTF-8 encoded passphrase bytes.
 * @return             0 on success (header decrypted), -1 on wrong password, -2 on format error.
 *
 * NOTE: Full PBKDF2 + AES-XTS decryption will be implemented in a future milestone.
 */
JNIEXPORT jint JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeParseHeader(
        JNIEnv *env,
        jclass /* clazz */,
        jbyteArray headerBytes,
        jbyteArray password) {
    if (headerBytes == nullptr || password == nullptr) {
        LOGE("nativeParseHeader: null argument");
        return -2;
    }

    jsize headerLen = env->GetArrayLength(headerBytes);
    if (headerLen < 512) {
        LOGE("nativeParseHeader: header buffer too short (%d bytes)", static_cast<int>(headerLen));
        return -2;
    }

    // TODO: implement PBKDF2 key derivation and AES-XTS decryption
    LOGI("nativeParseHeader: stub called, headerLen=%d", static_cast<int>(headerLen));
    return -1; // always "wrong password" until real crypto is wired up
}

} // extern "C"
