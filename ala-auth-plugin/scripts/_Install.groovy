//
// This script is executed by Grails after plugin was installed to project.
// This script is a Gant script so you can use all special variables provided
// by Gant (such as 'baseDir' which points on project base dir). You can
// use 'ant' to access a global instance of AntBuilder
//
// For example you can create directory under project tree:
//
//   ant.mkdir(dir:"${basedir}/grails-app/jobs")
//
// backup original project files
//ant.echo("Backing-up project files: index.gsp and layouts/main.gsp")
// copy over plugin files
ant.echo("NOTE: Please copy the plugin file: 'layouts/main.gsp' into your local app")

//try {
//    File layoutFile = new File(new File(new File(basedir, "grails-app"), "views/layouts"), "main.gsp")
//    def toLayoutFile =  "${basedir}/grails-app/views/layouts/main.gsp"
//    File indexFile = new File(new File(new File(basedir, "grails-app"), "views"), "index.gsp")
//    def toIndexFile =  "${basedir}/grails-app/views/index.gsp"
//
//    if (layoutFile.exists()) {
//        toLayoutFile += ".new"
//    }
//    if (indexFile.exists()) {
//        toIndexFile += ".new"
//    }
//    if (!(layoutFile.exists() && indexFile.exists())) {
//        // assume first time installation - backup original files first
//        if (layoutFile.exists()) {
//            ant.copy(file: "${basedir}/grails-app/views/layouts/main.gsp",
//                    toFile: "${basedir}/grails-app/views/layouts/main.gsp.bak")
//        }
//        if (indexFile.exists()) {
//            ant.copy(file: "${basedir}/grails-app/views/index.gsp",
//                    toFile: "${basedir}/grails-app/views/index.gsp.bak")
//        }
//    }
//
////layout file
//    ant.copy(file: "${pluginBasedir}/grails-app/views/layouts/main.gsp",
//             toFile: toLayoutFile,
//             overwrite: true)
//// index file
//    ant.copy(file: "${pluginBasedir}/grails-app/views/index.gsp",
//             toFile: toIndexFile,
//             overwrite: true)
//
//} catch (Exception ex) {
//    ant.echo("Error running install script: " + ex.message)
//}