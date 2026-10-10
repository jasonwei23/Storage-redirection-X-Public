"""执行真实媒体字段方法，覆盖原保存层级与晚写入物理路径的回归。"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_mount_metadata_scope import function_body

ROOT = Path(__file__).resolve().parents[2]
JAVA = shutil.which("java")
JAVAC = shutil.which("javac")


@unittest.skipUnless(JAVA and JAVAC, "需要 JDK 执行媒体字段回归")
class MediaStoreColumnsTest(unittest.TestCase):
    def test_mapping_and_provider_column_lifecycle(self):
        source = (ROOT / "java_src/org/srx/hook/Hooker.java").read_text(encoding="utf-8")
        signatures = [
            "private static ContentValuesPatch patchContentValues(",
            "public Object providerMediaFileColumnCallback(",
            "private static void restoreMediaFileBuildValues(",
            "private static void restoreMediaStoreVolumePrefix(",
            "private static void restoreContentValue(",
            "private static String buildMediaStoreProbePath(",
            "private static String relativePathFromStoragePath(",
            "private static String mediaStoreRelativePath(",
            "private static String mediaStorePhysicalRoot(",
            "private static String physicalRelativePath(",
            "private static String trimRelativePathSlash(",
            "private static String mediaStoreDisplayPath(",
            "private static String normalizeRelativePathValue(",
            "private static String relativePathFromDirectoryColumns(",
            "private static void patchDirectoryColumns(",
            "private static void patchRelativePathFromDataIfMissing(",
            "private static String firstString(",
            "private static int userIdFromUid(",
            "private static ContentValues copyIfNeeded(",
            "private static ContentValues findContentValues(",
            "private static Object[] unwrapArgs(",
            "private static boolean isInsertLikeMutation(",
            "private static final class ContentValuesPatch",
            "private static final class DownloadMediaPathPatch",
            "private static final class MediaFileBuildContext",
        ]
        methods = []
        for signature in signatures:
            start = source.index(signature)
            brace = source.index("{", start)
            methods.append(source[start:brace] + function_body(source, signature))
        fixture = r'''
import java.util.*;
import java.io.*;
import java.lang.reflect.Method;
public class ColumnsFixture {
  static final int ANDROID_APP_UID_START = 10000, ANDROID_USER_ID_OFFSET = 100000;
  static final ThreadLocal<MediaFileBuildContext> MEDIA_FILE_BUILD_CONTEXT = new ThreadLocal<>();
  static final ThreadLocal<Integer> MEDIA_PROVIDER_CALLER_UID = new ThreadLocal<>();
  static final ThreadLocal<String> MEDIA_PROVIDER_MUTATION_METHOD = new ThreadLocal<>();
  static class MediaStore {
    static class MediaColumns {
      static final String DATA = "_data", RELATIVE_PATH = "relative_path", DISPLAY_NAME = "_display_name";
    }
  }
  static class ContentValues extends HashMap<String,Object> {
    ContentValues() {}
    ContentValues(ContentValues v) { super(v); }
    String getAsString(String k) { Object v = get(k); return v == null ? null : v.toString(); }
  }
  static boolean sandbox, mappingEnabled = true, consumeContext = true, failBackup;
  static String generatedName = ".pending-123-XHS.jpg";
  Object target;
  static void logInfo(String s) {}
  static void rememberProviderRedirectSourceDirectory(String a,String b) {}
  static boolean hasUnsafeRelativePathSegment(String p) { return p.contains(".."); }
  static void rememberMediaStoreMutationPathHint(String p,ContentValues v,int uid) {}
  static void forceDirectMediaStoreWrite(ContentValues v) {}
  static DownloadMediaPathPatch rewriteDownloadPlaceholderPath(
      String p,ContentValues v,int uid,android.net.Uri uri) { return null; }
  static DownloadMediaPathPatch rewriteDownloadPlaceholderRelative(
      String p,String n,ContentValues v,int uid,android.net.Uri uri) { return null; }
  static ContentValues patchPendingDirectMediaUpdate(
      ContentValues p,ContentValues v,android.net.Uri uri) { return null; }
  static boolean mediaStoreValueLandsInSandbox(String p,int uid) { return sandbox; }
  // 外部依赖只模拟路由；目录拼接、字段修改和生命周期方法均从生产源码提取。
  static String rewriteStoragePathForValues(String p,int uid) {
    if (p == null) return null;
    return mappingEnabled ? p.replace("/DCIM/", "/Pictures/XHS/") : p;
  }
  static String resolveMediaStoreDirectPathForValues(String p,int uid) {
    String mapped = rewriteStoragePathForValues(p,uid);
    String root = "/storage/emulated/" + userIdFromUid(uid) + "/";
    String backend = "/data/media/" + userIdFromUid(uid) + "/";
    boolean needsSandbox = sandbox && !mapped.contains("/Android/data/");
    return mapped.replace(root, backend + (needsSandbox ? "Android/data/com.xingin.xhs/sdcard/" : ""));
  }
  Object callBackup(Object[] args) throws Throwable {
    ContentValues v = findContentValues(unwrapArgs(args));
    String p = buildMediaStoreProbePath(v.getAsString("relative_path"),
        v.getAsString("_display_name"),MEDIA_PROVIDER_CALLER_UID.get());
    String physical = resolveMediaStoreDirectPathForValues(p,MEDIA_PROVIDER_CALLER_UID.get());
    physical = physical.substring(0,physical.lastIndexOf('/') + 1) + generatedName;
    v.put("_data",physical);
    if (consumeContext) restoreMediaFileBuildValues(new Object[]{new Object[]{v}});
    // 模拟 ensureFileColumns 在 FileUtils 回调之后再次以 File.getAbsolutePath 覆盖 _data。
    v.put("_data",physical);
    if (failBackup) throw new IOException("模拟原方法失败");
    return "完成";
  }
  static void equal(Object expected,Object actual) {
    if (!Objects.equals(expected,actual)) throw new AssertionError(expected + " != " + actual);
  }
  static ContentValues values(String relative,String name) {
    ContentValues v = new ContentValues();
    v.put("relative_path",relative); v.put("_display_name",name);
    v.put("primary_directory","DCIM"); v.put("secondary_directory","Camera");
    return v;
  }
  static void checkMapping(boolean isolated,String key) throws Throwable {
    sandbox = isolated;
    ContentValues original = values("DCIM/","Camera/XHS.jpg");
    if (key.equals("display_name")) {
      original.remove("_display_name"); original.put(key,"Camera/XHS.jpg");
    }
    ContentValues patched = patchContentValues(original,10355,null,true).values;
    equal("Pictures/XHS/",patched.getAsString("relative_path"));
    // 文件名里的 Camera/ 交由系统清洗，不能移入相对目录或删除前缀。
    equal("Camera/XHS.jpg",patched.getAsString(key));
    String path = buildMediaStoreProbePath(patched.getAsString("relative_path"),
        firstString(patched,"_display_name","display_name"),10355);
    equal("/storage/emulated/0/Pictures/XHS/Camera_XHS.jpg",path);
    equal(isolated ? path : null,patched.getAsString("_data"));
    equal("DCIM/",original.getAsString("relative_path"));
    equal("Camera/XHS.jpg",original.getAsString(key));
  }
  static void checkColumns(boolean isolated,boolean consume,String relative,int uid) throws Throwable {
    sandbox = isolated; consumeContext = consume; failBackup = false;
    MEDIA_PROVIDER_CALLER_UID.set(uid); MEDIA_PROVIDER_MUTATION_METHOD.set("insert");
    ContentValues v = values(relative,"XHS.jpg");
    equal("完成",new ColumnsFixture().providerMediaFileColumnCallback(new Object[]{null,v}));
    String expected = "/storage/emulated/" + userIdFromUid(uid) + "/";
    if (isolated && consume) expected += "Android/data/com.xingin.xhs/sdcard/";
    expected += relative.replace("DCIM/","Pictures/XHS/") + generatedName;
    equal(expected,v.getAsString("_data"));
    equal(relative,v.getAsString("relative_path"));
    equal("DCIM",v.getAsString("primary_directory"));
    equal(null,MEDIA_FILE_BUILD_CONTEXT.get());
  }
  public static void main(String[] args) throws Throwable {
    // 真正的子目录只来自 RELATIVE_PATH；DISPLAY_NAME 的分隔符不是目录层级。
    equal("/storage/emulated/0/DCIM/Camera_XHS.jpg",
        buildMediaStoreProbePath("DCIM/","Camera/XHS.jpg",10355));
    equal("/storage/emulated/0/DCIM/Camera/XHS.jpg",
        buildMediaStoreProbePath("DCIM/Camera/","XHS.jpg",10355));
    equal("/storage/emulated/0/DCIM/Camera_XHS.jpg",
        buildMediaStoreProbePath("DCIM/","Camera\\XHS.jpg",10355));
    equal("/storage/emulated/0/DCIM/..__XHS.jpg",
        buildMediaStoreProbePath("DCIM/","..//XHS.jpg",10355));
    checkMapping(false,"_display_name"); checkMapping(true,"_display_name");
    checkMapping(false,"display_name"); checkMapping(true,"display_name");
    // 串起映射和 Provider 列处理，确认文件名含 Camera/ 的图片仍在目标根目录。
    sandbox = false; generatedName = "Camera_XHS.jpg";
    MEDIA_PROVIDER_CALLER_UID.set(10355); MEDIA_PROVIDER_MUTATION_METHOD.set("insert");
    ContentValues rootImage = patchContentValues(values("DCIM/","Camera/XHS.jpg"),10355,null,true).values;
    new ColumnsFixture().providerMediaFileColumnCallback(new Object[]{null,rootImage});
    equal("Pictures/XHS/",rootImage.getAsString("relative_path"));
    equal("/storage/emulated/0/Pictures/XHS/Camera_XHS.jpg",rootImage.getAsString("_data"));
    mappingEnabled = false; sandbox = false;
    ContentValues plain = values("DCIM/Camera/","XHS.jpg");
    equal(plain,patchContentValues(plain,10355,null,true).values);
    equal(null,plain.getAsString("_data"));
    mappingEnabled = true;
    ContentValues child = patchContentValues(values("DCIM/Camera/","XHS.jpg"),10355,null,true).values;
    equal("Pictures/XHS/Camera/",child.getAsString("relative_path"));
    equal("XHS.jpg",child.getAsString("_display_name"));
    for (String name : new String[]{".pending-123-XHS.jpg","XHS (1).jpg","Camera_XHS.jpg"}) {
      generatedName = name;
      checkColumns(false,true,"Pictures/XHS/Camera/",10355);
      checkColumns(false,true,"DCIM/Camera/",10355);
      checkColumns(true,true,"Pictures/XHS/Camera/",10355);
      checkColumns(true,false,"Pictures/XHS/Camera/",10355);
      checkColumns(false,true,"DCIM/Camera/",1010355);
    }
    // pending update 的提前返回分支也不能泄漏物理卷前缀。
    sandbox = false; consumeContext = true; generatedName = ".pending-123-XHS.jpg";
    MEDIA_PROVIDER_CALLER_UID.set(10355); MEDIA_PROVIDER_MUTATION_METHOD.set("update");
    MEDIA_FILE_BUILD_CONTEXT.set(new MediaFileBuildContext("/storage/emulated/0/Pictures/XHS/Camera/XHS.jpg"));
    ContentValues update = values("DCIM/Camera/","XHS.jpg");
    new ColumnsFixture().providerMediaFileColumnCallback(new Object[]{null,update});
    equal("/storage/emulated/0/Pictures/XHS/Camera/" + generatedName,update.getAsString("_data"));
    equal(null,MEDIA_FILE_BUILD_CONTEXT.get());
    // 原方法异常照常传播，临时目录字段和线程上下文必须收尾。
    MEDIA_PROVIDER_MUTATION_METHOD.set("insert"); sandbox = true; consumeContext = false; failBackup = true;
    ContentValues failing = values("Pictures/XHS/Camera/","XHS.jpg");
    try {
      new ColumnsFixture().providerMediaFileColumnCallback(new Object[]{null,failing});
      throw new AssertionError("原方法异常被吞掉");
    } catch (IOException expected) {}
    equal("Pictures/XHS/Camera/",failing.getAsString("relative_path"));
    equal(null,MEDIA_FILE_BUILD_CONTEXT.get());
  }
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stubs = {
                "android/net/Uri.java": "package android.net; public class Uri {}",
                "android/os/Binder.java": "package android.os; public class Binder { public static int getCallingUid() { return 10355; } }",
            }
            for path, content in stubs.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            (root / "ColumnsFixture.java").write_text(
                fixture + "\n".join(methods) + "\n}", encoding="utf-8"
            )
            compile_result = subprocess.run(
                [JAVAC, "-encoding", "UTF-8", "ColumnsFixture.java", *stubs],
                cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=60,
            )
            self.assertEqual(0, compile_result.returncode, compile_result.stderr)
            result = subprocess.run(
                [JAVA, "-cp", str(root), "ColumnsFixture"],
                cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=30,
            )
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
