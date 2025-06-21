SIM Card Management Application
===============================

This is not intended to be a general purpose application, but rather one with limited functionality, responding to a specific need. 

The application ensures secure and efficient management of telemetric SIM cards, providing both flexibility and control over network connections. The system comprises several key components:


Web Frontend
------------

This user-friendly interface allows for the assignment of SIM cards to clients. Enables the definition of rules governing permissible network connections between SIM cardsi and other endpoints. Clients can manage their own cards in a similar manner.

Independent Firewall Module
--------------------------

Responsible for creating appropriate rules on network firewalls. For security reasons, this module operates independently of the web application. The web application does not interact with this module directly. Instead, the module pulls the expected state of connections as needed.

Audit Module
------------

Provides a detailed trail of changes made in the configuration. Ensures transparency and accountability.

Policy Module
-------------

Configured independently of the web application. The web application and firewall configurator will verify with this module whether a connection someone is trying to establish is permitted.

