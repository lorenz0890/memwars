FROM rhub/ubuntu-gcc-release
#gcc:9.3
COPY ./ ./memwars
WORKDIR ./memwars
#RUN chmod +x run.sh
#RUN apt-get update && apt-get install -y libopencv-dev
RUN apt-get update && apt-get -y install cmake
RUN apt-get update && apt-get -y install nano
RUN ls
#RUN gcc -o memwars ./memwars.cpp
#CMD [./memwars]