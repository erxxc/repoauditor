import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry

fun extract(stream: java.io.InputStream, entry: JarEntry, destination: Path) {
    val output = destination.resolve(entry.name)
    Files.copy(stream, output)
}
