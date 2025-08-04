workspace "SIMMgr" {

    !identifiers hierarchical

    model {
        user = person "Client" {
            tags "Person"
        }
        admin = person "Admin" {
            tags "Person"
        }
        superadmin = person "SuperAdmin" {
            tags "Person"
        }

        simmgr = softwareSystem "SIMMgr" {
            simapp = container "SIM Manager Application" {
                simfront = component "SIM Web App"
                simapi = component "SIM API"
                simdb = component "SIM App DB" {
                    tags "Database"
                }

                simmgr.simapp.simfront -> simmgr.simapp.simapi "Uses"
                simmgr.simapp.simapi -> simmgr.simapp.simdb "Reads/Writes data"
            }
            adminapp = container "Supervisor Application" {
                adminfront = component "Admin Web App"
                adminapi = component "Admin API"
                policyapi = component "Policy API"
                policydb = component "Policy DB" {
                    tags "Database"
                }

                simmgr.adminapp.adminfront -> simmgr.adminapp.adminapi "Uses"
                simmgr.adminapp.adminapi -> simmgr.adminapp.policyapi "Reads/Writes policies"
                simmgr.adminapp.policyapi -> simmgr.adminapp.policydb "Reads/Writes data"
            }
            configapp = container "Configurator" {
                configapi = component "Configurator"
            }
            auditapp = container "Auditor" {
                auditapi = component "Auditor API"
                auditdb = component "Auditor DB" {
                    tags "Database"
                }
                simmgr.auditapp.auditapi -> simmgr.auditapp.auditdb "Reads/Writes data"
            }

            simmgr.simapp.simapi -> simmgr.adminapp.policyapi "Checks policy"
            simmgr.configapp.configapi -> simmgr.simapp.simapi "Downloads config changes"

            simmgr.adminapp.adminapi -> simmgr.auditapp.auditapi "Reads audit records"

            simmgr.configapp.configapi -> simmgr.adminapp.policyapi "Checks policy"
            simmgr.configapp.configapi -> simmgr.auditapp.auditapi "Sends config changes"
        }

        user -> simmgr.simapp.simfront "Uses"
        admin -> simmgr.simapp.simfront "Uses"
        superadmin -> simmgr.adminapp.adminfront "Uses"

        network = softwareSystem "Network"

        simmgr.configapp.configapi -> network "Uploads config"
    }
    views {
        systemContext simmgr "ContextView" {
            include *
            autolayout lr
        }
        container simmgr "MainAppsView" {
            include *
            autolayout lr
        }
        component simmgr.simapp "SIMAppView" {
            include *
            autolayout lr
        }
        component simmgr.adminapp "AdminAppView" {
            include *
            autolayout lr
        }
        component simmgr.configapp "ConfiguratorView" {
            include *
            autolayout lr
        }
        component simmgr.auditapp "AuditorView" {
            include *
            autolayout lr
        }

        styles {
            element "Element" {
                color Snow
                shape RoundedBox
            }
            element "Software System" {
                background Brown
            }
            element "Container" {
                background Chocolate
            }
            element "Component" {
                background DarkGoldenRod
            }
            element "Person" {
                background DarkSlateBlue
                shape Person
            }
            element "Database" {
                shape cylinder
            }
        }
    }
}
