package groovy.util.slurpersupport

/**
 * Compatibility bridge for libraries compiled against the pre-Groovy-4 package name.
 *
 * http-builder 0.7.x references groovy.util.slurpersupport.GPathResult in method
 * signatures. Groovy 4 moved this type to groovy.xml.slurpersupport.GPathResult.
 * Keeping this shim on the classpath allows those classes to load for JSON use-cases.
 */
abstract class GPathResult extends groovy.xml.slurpersupport.GPathResult {
    GPathResult(GPathResult parent, String name, String namespacePrefix, Map<String, String> namespaceTagHints) {
        super(parent, name, namespacePrefix, namespaceTagHints)
    }
}

