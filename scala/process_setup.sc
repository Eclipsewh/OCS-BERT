/* process.scala

  This script is responsible for performing taint-based program slicing.

  Input: Python File
  Output: txt

 */

import scala.util.matching.Regex
import scala.collection.mutable.ListBuffer
import scala.io.Source
import java.io.PrintWriter
import java.io.File
import java.io.{BufferedInputStream, FileInputStream}
import java.io.{BufferedWriter, FileWriter}
import java.util.zip.GZIPInputStream
import scala.sys.process._
import java.util.concurrent.{Executors, ExecutorService}
import java.util.concurrent.{Executors, ScheduledExecutorService, TimeUnit}
import java.util.concurrent.{Executors, ThreadPoolExecutor, TimeUnit}

import scala.concurrent.{Future, Await}
import scala.concurrent.duration._
import scala.util.{Failure, Success, Try}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

import scala.concurrent.ExecutionContext
import java.util.concurrent.TimeoutException

// Create an empty mutable list
var lineNumbers = ListBuffer.empty[Int]
val featureList: ListBuffer[String] = ListBuffer.empty[String]
val subdirectory = "path_to_your_folder"  // 

// Function to process the lines from empty flow
def LineFrom_emptyFlows(
    lineNode: List[io.shiftleft.codepropertygraph.generated.nodes.Call]
): Unit = {
  val sourceLinesInt: List[Int] =
    lineNode.map(_.lineNumber).flatten.map(_.toInt).distinct
  for (elem <- sourceLinesInt) {
    if (!lineNumbers.contains(elem)) {
      lineNumbers += elem
    }
  }
  println("LineFrom_emptyFlows:")
  sourceLinesInt.foreach(println)
}

// Function to process the lines in the flow
def process_Line(
    flows: Iterator[io.joern.dataflowengineoss.language.Path]
): Unit = {
  val att_lineNumbers = flows.dedup.l
    .flatMap(_.elements.flatMap {
      case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
        c.lineNumber
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        i.lineNumber
      case _ => None
    })
    .distinct
  // lineNumbers ++= att_lineNumbers.map(_.asInstanceOf[Integer])
  // lineNumbers = lineNumbers.distinct
  for (elem <- att_lineNumbers) {
    if (!lineNumbers.contains(elem)) {
      lineNumbers += elem
    }
  }
}

// Function to print the line numbers
def print_line(): Unit = {
  println(s"attack_line: $lineNumbers")
}


def get_code(filePath: String, version: String): Unit = {

  // File path
  // Get the filename from the file path

  // Extract the version part from the filename,
  // val version = filePath.split("/").dropRight(1).last
  // println(s"filename: $version")
  val outputFilePath = "slice_clean/" + version + ".txt"
  
  // Read file content
  val lines = Source.fromFile(filePath).getLines().map(_.trim).toList
  lineNumbers = lineNumbers.sorted
  
  // Filter and get the corresponding lines based on the line numbers
  val selectedLines =
    lineNumbers.flatMap(lineNumber => lines.lift(lineNumber - 1))

  // Print the results
  selectedLines.foreach(println)
  
  // Write the selected lines to the output file
  val writer = new PrintWriter(outputFilePath)
  selectedLines.foreach(line => writer.println(line))
  writer.close()

  // Calculate statistics and write feature data to a CSV file
  val totallineCount = lines.length
  val elementCount = lineNumbers.size
  val percentage = f"${elementCount.toDouble / totallineCount.toDouble * 100}%2.2f"
  val featureFilePath = s"feature/feature_$subdirectory.csv"
  val file = new File(featureFilePath)
  val writer2 = new BufferedWriter(new FileWriter(file, true))
  
  // If the file doesn't exist, write the header row
  if (!file.exists()) {
    writer2.write("version,percentage,totallineCount,elementCount,feature\n")
  }

  // Write the data row
  writer2.write(s"$version,$percentage%,$totallineCount,$elementCount,${featureList.mkString(",")}\n")

  writer2.close()
}

def get_setupPath(): Seq[String] = {
  def findSetupPyFiles(directory: String): Seq[String] = {
    val file = new File(directory)
    if (file.exists && file.isDirectory) {
      file.listFiles.flatMap { f =>
        if (f.isDirectory) {
          findSetupPyFiles(f.getPath)
        } else if (f.getName == "setup.py") {
          Seq(f.getPath)
        } else {
          Seq.empty[String]
        }
      }
    } else {
      Seq.empty[String]
    }
  }

  val datasetPath = s"/root/home/$subdirectory"
  val setupPyFiles = findSetupPyFiles(datasetPath)

  // Print the setup.py file paths
  setupPyFiles.foreach(println)
  return setupPyFiles
}

def get_code_all(filePath: String, version: String): Unit = {
  val outputFilePath = "slice_clean/" + version + ".txt"
  
  // Read file content
  val lines = Source.fromFile(filePath).getLines().map(_.trim).toList
  
  // Print the results (optional)
  //Lines.foreach(println)
  
  // Write all lines to the output file
  val writer = new PrintWriter(outputFilePath)
  lines.foreach(line => writer.println(line))
  writer.close()

  // Calculate statistics and write feature data to a CSV file
  val totallineCount = lines.length
  val elementCount = totallineCount
  val percentage = f"${elementCount.toDouble / totallineCount.toDouble * 100}%2.2f"
  val featureFilePath = s"feature/feature_$subdirectory.csv"
  val file = new File(featureFilePath)
  val writer2 = new BufferedWriter(new FileWriter(file, true))
  
  // If the file doesn't exist, write the header row
  if (!file.exists()) {
    writer2.write("version,percentage,totallineCount,elementCount,feature\n")
  }

  // Write the data row with an error message (for long process time)
  val err_msg = "long process time"
  writer2.write(s"$version,$percentage%,$totallineCount,$elementCount,$err_msg\n")

  writer2.close()
}


@main def exec(): Unit = {
  val res_path = "/opt/joern/joern-cli/slice_clean/"
  val res_directory = new File(res_path)
  val txtFiles = res_directory.listFiles
    .filter(_.isFile)
    .map(_.getName)
    .filter(_.endsWith(".txt"))
    .map(_.dropRight(4))

  val setupPyFiles: Seq[String] = get_setupPath()
     for (setupCurrentPath <- setupPyFiles) {
    val version = setupCurrentPath.split("/").dropRight(1).last
    println(s"filename: $version")
    
    if (!txtFiles.contains(version) && version != "detection_telegram-5.6") {
          //lineNumbers = ListBuffer.empty[Int]
	   //featureList: ListBuffer[String] = ListBuffer.empty[String]
        val future = Future {
          task(version, setupCurrentPath)
        }

      try {
        Await.result(future, 2.minute)
      } catch {
        case _: TimeoutException =>
          println("Task timed out, handling exception...")
           // Perform exception handling logic
          get_code_all(setupCurrentPath,version)
      }
    }
 }
}



def task(version:String, setupCurrentPath:String) =  {

  /*val res_path = "/home/wys/joern/joern-cli/slice_data/"
  val res_directory = new File(res_path)
  val txtFiles = res_directory.listFiles
    .filter(_.isFile)
    .map(_.getName)
    .filter(_.endsWith(".txt"))
    .map(_.dropRight(4))

  val setupPyFiles: Seq[String] = get_setupPath()
  for (setupCurrentPath <- setupPyFiles) {
    val version = setupCurrentPath.split("/").dropRight(1).last
    println(s"filename: $version")
    val interval = (version.length.toFloat / 4).toInt
    if (!txtFiles.contains(version) && version != "detection_telegram-5.6"&&interval == input) {*/

      importCode(setupCurrentPath, version)
      println("========================================================")
      println(s"===                 $version                         ===")
      println("========================================================")
      /*importCode(
    "/home/wys/dataset/pypi_malregistry/10Cent10/999.0.4/10Cent10-999.0.4/setup.py",
    "10Cent10"
  )*/
      // importCode("apache-log4j-test","log4j-test")
      lineNumbers.clear()
      featureList.clear()
      println(s"================att_lineNumbers is :$lineNumbers")
      val message = "Hello, world!"
      println(message)
      val outFile = "output/output.json"
      val sourceGroups = Map(
        "SensitiveMesgSource" -> Seq(
          "os.getlogin",
          "getpass.getuser",
          "pwd.getpwuid",
          "pwd.getpwnam",
          "ssh-copy-id",
          "OpenSSL.crypto",
          "os.sendfile",
          "os.write",
          "os.writev",
          "os.pwrite",
          "os.pwritev",
          "plistlib.writePlist",
          "plistlib.writePlistToResource",
          "io.IOBase.writelines",
          "io.RawIOBase.write",
          "io.BufferedIOBase.write",
          "io.TextIOBase.write",
          "tempfile.mkstemp",
          "tempfile.mkdtemp",
          "tempfile.TemporaryFile",
          "tempfile.NamedTemporaryFile",
          "tempfile.SpooledTemporaryFile",
          "open",
          "file",
          "os.fdopen",
          "os.open",
          "os.openpty",
          "shelve.DbfilenameShelf",
          "shelve.open",
          "anydbm.open",
          "dbm.open",
          "gdbm.open",
          "dbhash.open",
          "bsddb.hashopen",
          "bsddb.btopen",
          "bsddb.rnopen",
          "dumbdbm.open",
          "sqlite3.connect",
          "gzip.open",
          "gzip.GzipFile",
          "bz2.BZ2File",
          "zipfile.ZipFile",
          "tarfile.open",
          "tarfile.TarFile",
          "tarfile.TarFileCompat",
          "io.open",
          "io.FileIO",
          "aifc.open",
          "sunau.open",
          "sunau.openfp",
          "wave.open",
          "wave.openfp",
          "ossaudiodev.open"
        ),
        "NetworkSource" -> Seq(
          "urllib.urlopen",
          "urllib.URLopener",
          "urllib.FancyURLopener",
          "urllib2.urlopen",
          "urllib2.Request",
          "urllib2.OpenerDirector.open",
          "urllib2.FTPHandler.ftp_open",
          "urllib2.HTTPHandler.http_open",
          "urllib2.FileHandler.file_open",
          "urllib2.HTTPSHandler.https_open",
          "httplib.HTTPConnection",
          "httplib.HTTPSConnection",
          "ftplib.FTP_TLS",
          "ftplib.FTP",
          "poplib.POP3",
          "poplib.POP3_SSL",
          "imaplib.IMAP4",
          "imaplib.IMAP4_SSL",
          "imaplib.IMAP4_stream",
          "nntplib.NNTP",
          "smtplib.SMTP",
          "smtplib.LMTP",
          "smtplib.SMTP_SSL",
          "telnetlib.Telnet",
          "socket.create_connection",
          "socket",
          "socket.socketpair",
          "ssl.SSLSocket",
          "asyncio.open_connection",
          "asyncio.open_unix_connection",
          "http.client.HTTPConnection",
          "http.client.HTTPSConnection",
          "urllib.request.urlopen",
          "urllib.request.URLopener",
          "urllib.request.FancyURLopener"
        )
      )
      val sinkGroups = Map(
        "EnvCleanSink" -> Seq(
          "os.rename",
          "os.replace",
          "os.remove",
          "os.removedirs",
          "os.renames",
          "os.rmdir",
          "os.unlink",
          "shutil.rmtree",
          "shutil.move",
          "pathlib.Path.rename",
          "pathlib.Path.rmdir",
          "pathlib.Path.unlink",
          "shutil.copyfileobj",
          "shutil.copyfile",
          "shutil.copy",
          "shutil.copy2",
          "shutil.copytree",
          "shutil.make_archive"
        ),
        "SusProcessSink" -> Seq(
          "os.abort",
          "os.execl",
          "os.execle",
          "os.execlp",
          "os.execlpe",
          "os.execv",
          "os.execve",
          "os.execvp",
          "os.execvpe",
          "os._exit",
          "os.fork",
          "os.forkpty",
          "os.kill",
          "os.killpg",
          "os.spawnl",
          "os.spawnle",
          "os.spawnlp",
          "os.spawnlpe",
          "os.spawnv",
          "os.spawnve",
          "os.spawnvp",
          "os.spawnvpe",
          "os.startfile",
          "os.system",
          "os.register_at_fork",
          "os.popen",
          "os.popen2",
          "os.popen3",
          "os.popen4",
          "subprocess.run",
          "subprocess.call",
          "subprocess.check_call",
          "subprocess.check_output",
          "subprocess.Popen",
          "multiprocessing.Process",
          "multiprocessing.connection.Connection",
          "multiprocessing.connection.Connection.recv",
          "multiprocessing.connection.Connection.recv_bytes",
          "multiprocessing.connection.Connection.recv_bytes_into",
          "multiprocessing.connection.Connection.send",
          "multiprocessing.connection.Connection.send_bytes",
          "multiprocessing.Manager",
          "multiprocessing.managers.BaseManager",
          "multiprocessing.managers.SyncManager",
          "multiprocessing.Pool",
          "multiprocessing.pool.Pool",
          "signal.alarm",
          "signal.pause",
          "signal.siginterrupt",
          "signal.signal",
          "popen2.popen2",
          "popen2.popen3",
          "popen2.popen4",
          "popen2.Popen3",
          "popen2.Popen4",
          "sys.exit",
          "commands.getstatusoutput",
          "commands.getoutput",
          "commands.getstatus",
          "pipes.Template",
          "pty.fork",
          "pty.openpty",
          "pty.spawn",
          "threading.Thread",
          "asyncio.create_subprocess_exec",
          "asyncio.create_subprocess_shell",
          "concurrent.futures.Executor",
          "concurrent.futures.ThreadPoolExecutor",
          "concurrent.futures.ProcessPoolExecutor",
          "concurrent.futures.Future",
          "subprocess.getstatusoutput",
          "subprocess.getoutput",
          "shutil.copyfile"
        ),
        "Base64Sink" -> Seq(
          "base64.b64decode",
          "base64.standard_b64decode",
          "base64.urlsafe_b64decode",
          "base64.b32decode",
          "base64.b16decode",
          "base64.decode",
          "base64.decodestring"
        ),
        "ShellSink" -> Seq(
          "eval",
          "execfile",
          "import",
          "getattr",
          "delattr",
          "setattr",
          "compile",
          "exec",
          "ctypes.CDLL",
          "ctypes.OleDLL",
          "ctypes.WinDLL",
          "ctypes.PyDLL",
          "sys.exitfunc",
          "sys.settrace",
          "sys.setprofile",
          "code.interact",
          "code.compile_command",
          "code.InteractiveInterpreter",
          "code.InteractiveConsole",
          "codeop.compile_command",
          "codeop.Compile",
          "codeop.CommandCompiler",
          "imp.load_module",
          "imp.load_compiled",
          "imp.load_dynamic",
          "importlib.import_module",
          "zipimport.zipimporter",
          "pkgutil.ImpImporter",
          "pkgutil.ImpLoader",
          "pkgutil.find_loader",
          "pkgutil.get_importer",
          "pkgutil.get_loader",
          "modulefinder.AddPackagePath",
          "modulefinder.ReplacePackage",
          "runpy.run_module",
          "runpy.run_path",
          "parser.expr",
          "parser.suite",
          "py_compile.compile",
          "py_compile.main",
          "compileall.compile_dir",
          "compileall.compile_file",
          "compileall.compile_path",
          "dl.open",
          "atexit.register",
          "/bin/sh"
        ),
        "NetworkSink" -> Seq(
          "webbrower.open",
          "webbrower.open_new",
          "webbrower.open_new_tab",
          "wsgiref.simple_server.WSGIServer",
          "wsgiref.simple_server.make_server",
          "SocketServer.UDPServer",
          "SocketServer.TCPServer",
          "SocketServer.UnixStreamServer",
          "SocketServer.UnixDatagramServer",
          "SocketServer.BaseServer",
          "BaseHTTPServer.HTTPServer",
          "xmlrpclib.ServerProxy",
          "SimpleXMLRPCServer.SimpleXMLRPCServer",
          "DocXMLRPCServer.DocXMLRPCServer",
          "socketserver.UDPServer",
          "socketserver.TCPServer",
          "socketserver.UnixStreamServer",
          "socketserver.UnixDatagramServer",
          "socketserver.BaseServer",
          "socketserver.ForkingTCPServer",
          "socketserver.ForkingUDPServer",
          "socketserver.ThreadingTCPServer",
          "socketserver.ThreadingUDPServer",
          "asyncio.start_server",
          "asyncio.start_unix_server",
          "asyncore.dispatcher",
          "asyncore.dispatcher_with_send",
          "asynchat.async_chat",
          "urllib.request.build_opener",
          "http.server.HTTPServer",
          "http.server.ThreadingHTTPServer",
          "xmlrpc.client.ServerProxy",
          "xmlrpc.server.SimpleXMLRPCServer",
          "xmlrpc.server.DocXMLRPCServer",
          "asyncore.dispatcher.send",
          "socket.send",
          "socket.sendall",
          "socket.sendto",
          "socket.sendmsg",
          "socket.sendmsg_afalg",
          "socket.sendfile",
          "ssl.SSLSocket.write",
          "ssl.SSLSocket.send",
          "ssl.SSLSocket.sendall",
          "ssl.SSLSocket.sendfile",
          "dup2"
        )
      )

      val codeGroups = Map(
        "SuspiciousCmd" -> Seq(
          "/bin/sh",
          "/bin/bash",
          "passwd",
          "sudo",
          "powershell",
          "cmd",
          "__builtins__",
          "pip",
          "C:",
          "D:"
        )
      )
      def ipPattern = """\d+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\d+""".r
      def httpPattern = """.*?https?://\S+.*?""".r
      def basePattern =
        """.*?^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$.*?""".r
      val patternGroups = Map(
        "urlPattern" -> Seq(httpPattern, ipPattern)
        // "base64s" -> Seq(basePattern)
      )
      val toRemove = Set("int","import","Setup","len","list","map","getattr","main","str","sub") 
      // find source-sink lines
      val allFlows = for {
        (sourceGroup, sources) <- sourceGroups
        (sinkGroup, sinks) <- sinkGroups
      } yield {
        val sourceMethods = cpg.call.name
        .filterNot(toRemove.contains)
          .filter { methodName =>
            sources.exists(_.contains(methodName))
          }
          .toList
          .distinct
        val sourceInput = cpg.call.name
        .filterNot(toRemove.contains)
          .filter { methodName =>
            sources.exists(_.contains(methodName))
          }
          .toList
          .distinct

        val sinkMethods = cpg.call.name
        .filterNot(toRemove.contains)
          .filter { methodName =>
            sinks.exists(_.contains(methodName))
          }
          .toList
          .distinct

        println(s"sourceMethods:$sourceMethods,sinkMethods:$sinkMethods")
        (sinkMethods, sourceMethods) match {
          // case (Nil, _) => sourceMethods.foreach(s => LineFrom_emptyFlows(cpg.call.name(s).toList))
          // case (_, Nil) => sinkMethods.foreach(s => LineFrom_emptyFlows(cpg.call.name(s).toList))
           case (_, Nil) => // when sinkMethods is empty
                 for {
                     sink <- sinkMethods            
                          } {
              //println(s"AttGroup:  source:$source,sink:$sink")
            
              def s2 = cpg.call.name(sink)
               LineFrom_emptyFlows(s2.toList)
                        
                  
                // LineFrom_emptyFlows(c2.toList)
                 if (!featureList.contains(sink)) {
                  featureList += sink
                  //print("+",sink)
                }
                }
          case (Nil, _) => // when sourceMethods is empty
            for {
            
              source <- sourceMethods
                          } {
              //println(s"AttGroup:  source:$source,sink:$sink")
              def s1 = cpg.call.name(source)
              
            LineFrom_emptyFlows(s1.toList)
                
                // LineFrom_emptyFlows(c2.toList)
                 if (!featureList.contains(source)) {
                  featureList += source
                  //print("+",source)
                }
                }          
          case (_, _) =>
            for {
              sink <- sinkMethods
              source <- sourceMethods
              if sink != source
            } {
              //println(s"AttGroup:  source:$source,sink:$sink")
              def s1 = cpg.call.name(source)
              def s2 = cpg.call.name(sink)
              val flows = s2.reachableByFlows(s1)
              // println(s"-----------------flows is :$flows--------------------")
              if (flows.isEmpty) {
                // LineFrom_emptyFlows(s1.toList)
                // LineFrom_emptyFlows(s2.toList)
              } else {
                process_Line(flows)
                if (!featureList.contains(source)) {
                  featureList += source
                }
                if (!featureList.contains(sink)) {
                  featureList += sink
                }
              }
              
                 if(!s1.isEmpty){
                    
            LineFrom_emptyFlows(s1.toList)
                
                // LineFrom_emptyFlows(c2.toList)
                 if (!featureList.contains(source)) {
                  featureList += source
                  //print("+",source)
                }
              }
              
              if(!s2.isEmpty){
              
              LineFrom_emptyFlows(s2.toList)
                        
                  
                // LineFrom_emptyFlows(c2.toList)
                 if (!featureList.contains(sink)) {
                  featureList += sink
                  //print("+",sink)
                }
              }
              //println(s2.reachableByFlows(s1).dedup.p)
            }
        }
      }
      /*
 def stringsWithBin = cpg.call.filter(_.code.contains("/bin"))
 def ss2 = cpg.call.name("spawn")
 println(ss2.reachableByFlows(stringsWithBin).dedup.p)
       */

      println("------------------cmdFlows----------------------")
      val cmdFlows = for {
        (codeGroup, code_sources) <- codeGroups
        (sinkGroup, sinks) <- sinkGroups
      } yield {
        val sinkMethods = cpg.call.name
        .filterNot(toRemove.contains)
          .filter { methodName =>
            sinks.exists(_.contains(methodName))
          }
          .toList
          .distinct
        if (codeGroup == "SuspiciousCmd") {
          for {
            sink <- sinkMethods
            code_source <- code_sources
          } {
            // println(s"code_source:$code_source,sink:$sink")
            def c1 = cpg.call.filter(_.code.contains(code_source))
            def c2 = cpg.call.name(sink)
            if (c1.nonEmpty) {
              val flows = c2.reachableByFlows(c1)
              //println(s"-----------------flows is :$flows--------------------")
              if (flows.isEmpty) {
                LineFrom_emptyFlows(c1.toList)
                // LineFrom_emptyFlows(c2.toList)
                 if (!featureList.contains(code_source)) {
                  featureList += code_source
                }
              } else {
                process_Line(flows)
                if (!featureList.contains(code_source)) {
                  featureList += code_source
                }
                if (!featureList.contains(sink)) {
                  featureList += sink
                }
              }

              // process_Line(flows)
              //println(c2.reachableByFlows(c1).dedup.p)

            }

          }

        }
      }
      println("------------------cmdFlows end----------------------")

      println("------------------patternFlows start----------------------")
      val ptFlows = for {
        (ptGroup, pt_sources) <- patternGroups
        (sinkGroup, sinks) <- sinkGroups
      } yield {
        val sinkMethods = cpg.call.name
        .filterNot(toRemove.contains)
          .filter { methodName =>
            sinks.exists(_.contains(methodName))
          }
          .toList
          .distinct
        // if (ptGroup == "urlPattern") {
        for {
          sink <- sinkMethods
          urlPattern <- pt_sources
        } {

          def regex = urlPattern
          // def regex = """\d+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\d+""".r
          def c1 = cpg.call
            .filter(call =>
              call.argument.code.exists(str => regex.findFirstIn(str).isDefined)
            )
            .groupBy(_.lineNumber)
            .map { case (_, calls) => calls.head }
            .toIterator
          def c2 = cpg.call.name(sink)
          //println(s"c2: $c2.dedup.l")
          //println(s"c1: $c1.dedup.l")
          
          if (c1.nonEmpty) {
            print_line()
            println(s"Pattern Group:   c1:$ptGroup ,sink:$sink")
            val flows = c2.reachableByFlows(c1)
            if (flows.isEmpty) {
              // LineFrom_emptyFlows(c1.toList)
              // LineFrom_emptyFlows(c2.toList)
            } else {
              process_Line(flows)
                if (!featureList.contains(pt_sources)) {
                  featureList += ptGroup
                }
                if (!featureList.contains(sink)) {
                  featureList += sink
                }
            }

            // process_Line(flows)
            //println(c2.reachableByFlows(c1).dedup.p)
          }

        }
        // }

      }
      println("------------------patternFlows end----------------------")

      print_line()
      get_code(setupCurrentPath, version)
      println("------------------get code end----------------------")
      // println( cpg.method("spawn").callIn.filter(_.code.contains("/bin")).dedup.p)
      /*
    val flows = sinkMethods.flatMap { sink =>
      sourceMethods.flatMap { source =>
          cpg.method.name(sink)
          .reachableByFlows(source)
          .map(_.toString)
      }
    }

    (sourceGroup, sinkGroup) -> flows
  }
  allFlows.foreach(println)
       */
      // output to file
      // allFlows.values.flatten |> outFile


}
