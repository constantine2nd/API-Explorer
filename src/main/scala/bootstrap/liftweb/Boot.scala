/**
Open Bank Project - Transparency / Social Finance Web Application
Copyright (C) 2011, 2012, TESOBE / Music Pictures Ltd

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Email: contact@tesobe.com
TESOBE / Music Pictures Ltd
Osloerstrasse 16/17
Berlin 13359, Germany

  This product includes software developed at
  TESOBE (http://www.tesobe.com/)
  by
  Simon Redfern : simon AT tesobe DOT com
  Stefan Bethge : stefan AT tesobe DOT com
  Everett Sochowski : everett AT tesobe DOT com
  Ayoub Benali: ayoub AT tesobe DOT com

 */
package bootstrap.liftweb


import net.liftweb._
import util._
import common._
import http._
import sitemap._
import Loc._
import Helpers._
import net.liftmodules.widgets.tablesorter.TableSorter
import java.io.FileInputStream
import java.io.File

import code.lib.OAuthClient
import code.util.{Helper, MyExceptionLogger}
import code.util.Helper.MdcLoggable
import org.apache.commons.io.FileUtils

/**
 * A class that's instantiated early and run.  It allows the application
 * to modify lift's environment
 */
class Boot extends MdcLoggable{
  def boot {

    MDC.put( ("host", Helper.getHostname()) )

    val runningMode = Props.mode match {
      case Props.RunModes.Production => "Production mode"
      case Props.RunModes.Staging => "Staging mode"
      case Props.RunModes.Development => "Development mode"
      case Props.RunModes.Test => "test mode"
      case _ => "other mode"
    }

    logger.info("running mode: " + runningMode)

    val contextPath = LiftRules.context.path
    val propsPath = tryo{Box.legacyNullTest(System.getProperty("props.resource.dir"))}.toList.flatten

    logger.info("external props folder: " + propsPath)

    /**
     * Where this application looks for props files:
     *
     * All properties files follow the standard lift naming scheme for order of preference (see https://www.assembla.com/wiki/show/liftweb/Properties)
     * within a directory.
     *
     * The first choice of directory is $props.resource.dir/CONTEXT_PATH where $props.resource.dir is the java option set via -Dprops.resource.dir=...
     * The second choice of directory is $props.resource.dir
     *
     * For example, on a production system:
     *
     * thing1.example.com with context path /thing1
     *
     * Looks first in (outside of war file): $props.resource.dir/thing1, following the normal lift naming rules (e.g. production.default.props)
     * Looks second in (outside of war file): $props.resource.dir, following the normal lift naming rules (e.g. production.default.props)
     * Looks third in the war file
     *
     * and
     *
     * thing2.example.com with context path /thing2
     *
     * Looks first in (outside of war file): $props.resource.dir/thing2 , following the normal lift naming rules (e.g. production.default.props)
     * Looks second in (outside of war file): $props.resource.dir, following the normal lift naming rules (e.g. production.default.props)
     * Looks third in the war file, following the normal lift naming rules
     *
     */

    val firstChoicePropsDir = for {
      propsPath <- propsPath
    } yield {
      Props.toTry.map {
        f => {
          val name = propsPath + contextPath + f() + "props"
          name -> { () => tryo{new FileInputStream(new File(name))} }
        }
      }
    }

    val secondChoicePropsDir = for {
      propsPath <- propsPath
    } yield {
      Props.toTry.map {
        f => {
          val name = propsPath +  f() + "props"
          name -> { () => tryo{new FileInputStream(new File(name))} }
        }
      }
    }

    Props.whereToLook = () => {
      firstChoicePropsDir.toList.flatten ::: secondChoicePropsDir.toList.flatten
    }

    if(Helper.getPropsValue("defaultAuthProvider").isEmpty) {
      throw new Exception("defaultAuthProvider must be specified in the props file!")
    }

    def check(bool: Boolean) : Box[LiftResponse] = {
      if(bool){
        Empty
      }else{
        Full(PlainTextResponse("unauthorized"))
      }
    }

    def logOrReturnResult[T](result : Box[T]) : Box[T] = {
      result match {
        case Failure(msg, _, _) => logger.warn("Problem getting url " + tryo{S.uri} + ": " + msg)
        case _ => //do nothing
      }
      result
    }



    // Build SiteMap


    val sitemap = List(
      Menu.i("OBP API Explorer") / "api-explorer",
      Menu.i("Home") / "index",
      Menu.i("Glossary") / "glossary",
      Menu.i("Message Docs") / "message-docs",
      Menu.i("More") / "more",
      Menu.i("OAuth Callback") / "oauthcallback" >> EarlyResponse(() => {
        OAuthClient.handleCallback()
      })
    )

    LiftRules.setSiteMap(SiteMap.build(sitemap.toArray))

    LiftRules.addToPackages("code")

    // Use jQuery from js directory
    LiftRules.jsArtifacts = net.liftweb.http.js.jquery.JQueryArtifacts

    //Show the spinny image when an Ajax call starts
    LiftRules.ajaxStart =
      Full(() => LiftRules.jsArtifacts.show("ajax-loader").cmd)

    // Make the spinny image go away when it ends
    LiftRules.ajaxEnd =
      Full(() => LiftRules.jsArtifacts.hide("ajax-loader").cmd)

    // Force the request to be UTF-8
    LiftRules.early.append(_.setCharacterEncoding("UTF-8"))

    // Use HTML5 for rendering
    LiftRules.htmlProperties.default.set((r: Req) =>
      new Html5Properties(r.userAgent))

    LiftRules.explicitlyParsedSuffixes = Helpers.knownSuffixes &~ (Set("com"))

    TableSorter.init

    LiftRules.exceptionHandler.prepend{
      case MyExceptionLogger(_, _, t) => throw t // this will never happen
    }



    LiftRules.uriNotFound.prepend(NamedPF("404handler"){ case (req,failure) =>
      NotFoundAsTemplate(ParsePath(List("404"),"html",true,false)) })

    //If use_custom_webapp=true, this will copy all the files from `OBP-API/obp-api/src/main/webapp` to `OBP-API/obp-api/src/main/resources/custom_webapp`
    if (Helper.getPropsAsBoolValue("use_custom_webapp", false)){
      
      def backupWebappFolder(dir: File) = {
        // inserts correct file path separator on *nix and Windows
        // works on *nix
        // works on Windows
        val backupPath: java.nio.file.Path = java.nio.file.Paths.get(dir.getParent(), "webapp_initial")
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
        val backupPath: java.nio.file.Path = java.nio.file.Paths.get(destDir.getParent(), "webapp_initial")
        val directoryExists = java.nio.file.Files.exists(backupPath)
        if(directoryExists) { // Revert initial state
          val backUpDir = new File(backupPath.toUri.getPath)
          FileUtils.copyDirectory(backUpDir, destDir)
        }
      }
    }
  }
}
