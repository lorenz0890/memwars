# memwars
This little game is supposed to provide a skeleton implementation for the planned 2021 
hackathon organized by the students union of the Computer Science Faculty of
University of Vienna.

Last Man Standing Tournament:
For the provided memory attack pattern, each student provides his or her targetting
(i.e. process selection, memory adress range selection and payload creation) implementation.
All processes are then started in a safe environment (e.g. Ubuntu 18.04 Docker) and over 100
rounds of 5 minutes each, the implementations participating are evaluated as follows:
.) Last man standing: +10 points
.) Survived till end of round: +1 point
.) Killed docker container (i.e. broke OS) -10 points

