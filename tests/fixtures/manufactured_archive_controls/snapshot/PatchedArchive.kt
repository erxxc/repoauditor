import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry

fun extract(stream: java.io.InputStream, entry: JarEntry, destination: Path) {
    val root = destination.normalize()
    val output = root.resolve(entry.name).normalize()
    require(output.startsWith(root))
    Files.copy(stream, output)
}
