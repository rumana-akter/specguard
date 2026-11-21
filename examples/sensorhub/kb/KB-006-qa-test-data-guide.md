+++
id = "KB-006"
title = "QA guide to the operations test database"
topics = ["qa-data"]
label = "internal"
+++
Calibration offsets are in degrees Celsius and should lie within +/-0.5.
Gains should lie between 0.95 and 1.05. Query only the columns you need;
customer contact details and technician names are restricted and are not
needed for calibration or alarm analysis. Use aggregates where possible.
