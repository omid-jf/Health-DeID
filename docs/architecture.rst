Architecture
============

Health-DeID is a single-user desktop research application with three entry
points over one implementation: Flask UI, Typer CLI, and Python API.

Package map
-----------

.. code-block:: text

   src/health_deid/
   ├── api.py        public Python interface
   ├── cli.py        command-line interface
   ├── ui/           Flask routes, Bootstrap templates, and small JavaScript helpers
   ├── core/         pure taxonomy, resolution, date, and rendering functions
   ├── models/       Pydantic configuration and domain records
   ├── backends/     AWS adapters, local rules, chunking, and Faker replacements
   ├── pipeline/     orchestration, review, reporting, revision, and export
   └── storage/      SQLite schema and transaction helpers

The project deliberately avoids service containers, database ORMs, web
framework extensions, and custom concurrency frameworks. Pipeline code calls
focused repositories directly. Flask routes use server-rendered Jinja and
Bootstrap components.

Durable execution
-----------------

Each run owns one SQLite database and one file lock. Work items, backend
attempts, findings, transformations, review decisions, errors, usage, and
exports are committed as processing advances. A restarted process can recover
interrupted states and continue without repeating completed requests.

The processing sequence is:

.. code-block:: text

   input → detection and rules → draft de-identification → validation → review → final de-identification

Export is an explicit action. A revised run receives a new database, copies
compatible completed detector work, and reruns local rules and every downstream
de-identification step. The parent remains unchanged.

AWS execution
-------------

Detection and validation use ``ThreadPoolExecutor`` with a configurable worker
count that defaults to 2. Botocore standard retry mode handles transient
transport behavior. The only application-level retry escalation is the fixed
validator token sequence used after an explicitly truncated response. A
systemic AWS error stops the batch so a credentials or account problem is not
repeated across the remaining records.
