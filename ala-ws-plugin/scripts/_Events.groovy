eventCompileStart = {
    println "Compiling Bean Validation AST Transformation (must happen before the classes being transformed)..."
    println "Compiling AST classes to ${classesDir}"
    def sourcePath = "${alaWsPluginPluginDir}/src"
    def destPath = "${classesDir}"

    ant.mkdir(dir: "${destPath}/META-INF")
    ant.groovyc(destdir: destPath,
            encoding: "UTF-8") {
        src(path: "${sourcePath}/groovy")
    }

    ant.copy(todir: "${destPath}/META-INF") {
        fileset dir: "${sourcePath}/groovy/META-INF"
    }

    ant.copy(todir: "${destPath}") {
        fileset dir: "${alaWsPluginPluginDir}/grails-app/i18n"
    }

    grailsSettings.compileDependencies << new File(destPath)
    classpathSet = false
    classpath()
}
