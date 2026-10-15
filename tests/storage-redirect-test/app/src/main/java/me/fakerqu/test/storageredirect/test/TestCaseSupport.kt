package me.fakerqu.test.storageredirect.test

/** 失败取证：压缩版 /proc/self/mountinfo（只留 emulated/srx/data-media 相关条目，含本进程 pid）。 */
internal fun mountInfoSnapshot(): String =
    try {
      val lines =
          java.io.File("/proc/self/mountinfo").readLines().filter { line ->
            line.contains("/storage/emulated") ||
                line.contains("srx") ||
                line.contains("/data/media") ||
                line.contains("emulated")
          }
      "pid=${android.os.Process.myPid()} mounts=[" +
          lines.joinToString(" | ") { line ->
            val parts = line.split(" ")
            val sep = parts.indexOfFirst { it == "-" }
            if (sep > 1) {
              val target = parts.drop(4).dropLast(1).joinToString(" ")
              "${target}<-${parts.getOrNull(sep + 1)}:${parts.getOrNull(sep + 2)}"
            } else {
              line.take(90)
            }
          } +
          "]"
    } catch (e: Exception) {
      "mountinfo-unavailable: ${e.message}"
    }

internal inline fun TestCase.measure(block: () -> TestResult): TestResult {
  val startedAt = System.currentTimeMillis()
  return try {
    val outcome = block()
    if (outcome.testCase != this) {
      outcome.copy(
          testCase = this,
          durationMs = System.currentTimeMillis() - startedAt,
      )
    } else {
      outcome.copy(durationMs = System.currentTimeMillis() - startedAt)
    }
  } catch (e: Exception) {
    // 失败取证：写入类 ENOENT 从未到达模块 FUSE 回调，需要写入进程当时的挂载栈
    // （模块 FUSE 在不在、挂在哪一层）来区分「namespace 半就绪」与「下层视图缺失」。
    TestResult(
        testCase = this,
        passed = false,
        message =
            (e.message ?: e.javaClass.simpleName) + " [" + mountInfoSnapshot().take(1200) + "]",
        durationMs = System.currentTimeMillis() - startedAt,
        error = e.stackTraceToString(),
    )
  }
}

internal fun TestCase.pass(
    message: String,
    metadata: Map<String, String> = emptyMap(),
): TestResult = TestResult(testCase = this, passed = true, message = message, metadata = metadata)

internal fun TestCase.fail(
    message: String,
    metadata: Map<String, String> = emptyMap(),
): TestResult = TestResult(testCase = this, passed = false, message = message, metadata = metadata)
