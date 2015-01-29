//
// This script is executed by Grails during application upgrade ('grails upgrade'
// command). This script is a Gant script so you can use all special variables
// provided by Gant (such as 'baseDir' which points on project base dir). You can
// use 'ant' to access a global instance of AntBuilder
//
// For example you can create directory under project tree:
//
//    ant.mkdir(dir:"${basedir}/grails-app/jobs")
//

//evaluate(new File("_Install.groovy"))

ant.echo("NOTE: Please copy the plugin file: 'layouts/main.gsp' into your local app and check for changed against your local copy, as it may have changed")
