eventCompileStart = { target ->
    println "Compiling Bean Validation AST Transformation (must happen before the classes being transformed)..."
    println "Compiling AST classes to ${classesDir}"
    def sourcePath = "${alaWsPluginPluginDir}/src"
    def destPath = "${classesDir}"

    compileAST(alaWsPluginPluginDir, classesDir)
    ant.sequential {
//        mkdir(dir: destPath)
//        groovyc(destdir: destPath,
//                encoding: "UTF-8") {
//            src(path: "${sourcePath}/groovy")
//        }
        copy(todir: "${destPath}") {
            fileset dir: "${alaWsPluginPluginDir}/grails-app/i18n"
        }
    }

    grailsSettings.compileDependencies << new File(destPath)
    classpathSet = false
    classpath()
}

def compileAST(def srcBaseDir, def destDir) {
    ant.sequential {
      echo "Precompiling AST Transformations ..."
      echo "src ${srcBaseDir} ${destDir}"
      path id: "grails.compile.classpath", compileClasspath
      def classpathId = "grails.compile.classpath"
      mkdir dir: destDir
      groovyc(destdir: destDir,
          srcDir: "$srcBaseDir/src/groovy",
          classpathref: classpathId,
          verbose: grailsSettings.verboseCompile,
          stacktrace: "yes",
          encoding: "UTF-8")
      echo "done precompiling AST Transformations"
    }
}