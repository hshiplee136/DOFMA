# DOFMA System
**Real-time Detection of Fileless Malware through the Analysis of Process Dumps**

## About
The DOFMA System was designed by Henry Shiplee as part of the University of the West of England Cyber Security Research Project.

Included in this repository is the code for the DOFMA System, the pickled machine learning (ML) models, the datasets they were trained on, and the results.

## Installation
Download the files, set up folders, and run!

(Folder configuration can be edited within the code)

### Dependencies
The DOFMA System requires the usage of minidump to dump process information and write it to a log (Memory, Modules, or Threads), however it is not restricted to this. Alternative code can be used to achieve the same result.

The DOFMA System also requires the Sklearn library, the Pandas library, the Numpy library, and the Psutil library.

## Usage
The DOFMA System is designed to create a dump of a process, convert it into a CSV file, and then scan it using a ML classifier to predict whether the process has been infected by fileless malware.

Unfortunately, the results were less than satisfactory...

## References
minidump by skelsec - https://github.com/skelsec/minidump
