modules = {
    core {
        dependsOn 'jquery'
        resource url: [dir:'js', file:'html5.js', plugin: "ala-auth-plugin"], wrapper: { s -> "<!--[if lt IE 9]>$s<![endif]-->" }, disposition: 'head'
    }

    application {
        // implement in client app
    }

}
