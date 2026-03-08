#!/bin/bash
cd ~/acase
python3 -m http.server 9000 &
sleep 2
firefox http://localhost:9000/reports/acase_dashboard_complete.html
