package bootstrap.liftweb

import java.io.File

import code.util.Helper
import code.util.Helper.MdcLoggable
import net.liftweb.http.LiftRules
import org.apache.commons.io.FileUtils

object BootUtil extends MdcLoggable {
  /*
Return the git commit. If we can't for some reason (not a git root etc) then log and return ""
 */
  def gitCommit : String = {
    val commit = try {
      val properties = new java.util.Properties()
      logger.debug("Before getResourceAsStream git.properties")
      properties.load(getClass().getClassLoader().getResourceAsStream("git.properties"))
      logger.debug("Before get Property git.commit.id")
      properties.getProperty("git.commit.id", "")
    } catch {
      case e : Throwable => {
        logger.warn("gitCommit says: Could not return git commit. Does resources/git.properties exist?")
        logger.error(s"Exception in gitCommit: $e")
        "" // Return empty string
      }
    }
    commit
  }
  
  def applyCustomWebappRules(): Unit = {
    //If use_custom_webapp=true, this will copy all the files from `OBP-API/obp-api/src/main/webapp` to `OBP-API/obp-api/src/main/resources/custom_webapp`
    if (Helper.getPropsAsBoolValue("use_custom_webapp", false)){

      def backupWebappFolder(dir: File) = {
        // inserts correct file path separator on *nix and Windows
        // works on *nix
        // works on Windows
        val backupPath: java.nio.file.Path = java.nio.file.Paths.get(dir.getParent(), "webapp_" + gitCommit)
        val directoryExists = java.nio.file.Files.exists(backupPath)
        if(!directoryExists) {
          import java.nio.file.Files
          Files.createDirectories(backupPath)
          val backUpDir = new File(backupPath.toUri.getPath)
          FileUtils.copyDirectory(dir, backUpDir)
        }
      }

      //this `LiftRules.getResource` will get the path of `OBP-API/obp-api/src/main/webapp`: 
      LiftRules.getResource("/").map { url =>
        // this following will get the path of `OBP-API/obp-api/src/main/resources/custom_webapp`
        val source = if (getClass().getClassLoader().getResource("custom_webapp") == null)
          throw new RuntimeException("If you set `use_custom_webapp = true`, custom_webapp folder can not be Empty!!")
        else
          getClass().getClassLoader().getResource("custom_webapp").getPath
        val srcDir = new File(source);

        // The destination directory to copy to. This directory
        // doesn't exists and will be created during the copy
        // directory process.
        val destDir = new File(url.getPath)

        backupWebappFolder(destDir)

        // Copy source directory into destination directory
        // including its child directories and files. When
        // the destination directory is not exists it will
        // be created. This copy process also preserve the
        // date information of the file.
        FileUtils.copyDirectory(srcDir, destDir)
      }
    } else {
      //this `LiftRules.getResource` will get the path of `OBP-API/obp-api/src/main/webapp`: 
      LiftRules.getResource("/").map { url =>
        val destDir = new File(url.getPath)
        val backupPath: java.nio.file.Path = java.nio.file.Paths.get(destDir.getParent(), "webapp_" + gitCommit)
        val directoryExists = java.nio.file.Files.exists(backupPath)
        if(directoryExists) { // Revert initial state
          val backUpDir = new File(backupPath.toUri.getPath)
          FileUtils.copyDirectory(backUpDir, destDir)
        }
      }
    }
  }

}
