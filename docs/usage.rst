Usage
=====

Install
-------

Health-DeID supports Python 3.12 through 3.14.

.. code-block:: console

   pip install health-deid

The package includes Flask and botocore CRT support. AWS backends use the
normal boto3 credential and region chain; the UI never asks for credentials.

UI
--

Launch the primary interface with one fixed runs directory:

.. code-block:: console

   health-deid ui --reviewer "Reviewer Name" --runs-dir runs

The server accepts loopback hosts only and is intended for one person on a
laptop or desktop. Supply a run directory or ``run.sqlite`` path as the
optional positional argument to open that run immediately.

CLI
---

.. code-block:: console

   health-deid check config.yaml
   health-deid run config.yaml
   health-deid status runs/RUN_ID
   health-deid resume runs/RUN_ID
   health-deid retry runs/RUN_ID --stage validation --failed

Create a revised run while leaving the parent unchanged:

.. code-block:: console

   health-deid revise runs/RUN_ID revised.yaml \
     --reason "change replacement policy"

Add ``--rerun-detection`` only when authorizing a new paid detector pass.

Python API
----------

.. code-block:: python

   from health_deid import create_run, open_run

   run = create_run("config.yaml").execute()
   print(run.status())

   reopened = open_run(run.run_dir).resume()
   revised = reopened.revise(
       "revised.yaml",
       reason="change replacement policy",
   )

Export
------

``ready_only`` exports records with current final output. ``all_records`` keeps
the imported records and adds operational status fields.

.. code-block:: console

   health-deid export runs/RUN_ID final.parquet \
     --mode ready_only \
     --column record_id \
     --column final_text

Select source text, identifiers, or original structured PHI only when they are
required. The run database always
contains source clinical data and must remain protected as PHI.
