OpenFastPathGen2 is a spin-off of OpenFastPath project.
===============================================================================

Intent and purpose:
-------------------------------------------------------------------------------

OpenFastPathGen2 is a code design exercise intended to provide an overall
improvement of functionality offered by OpenFastPath project while exploring
utilization in small devices.

OpenFastPathGen2 does not target the API or design compatibility with
OpenFastPath project. More, rapid API or design changes are expected as part of
the new incubation phase.


OpenFastPath general info
===============================================================================


Intent and purpose:
-------------------------------------------------------------------------------
The intent of this project is to enable accelerated routing/forwarding for
IPv4 and IPv6, tunneling and termination for a variety of protocols.
Unsupported functionality is provided by the host OS networking stack
(slowpath).

OpenFastPath functionality is provided as a library to Fast Path applications
that use ODP run to completion execution model and framework. DPDK is supported
through the ODP-DPDK layer.

Termination of protocols with POSIX interface (socket) for legacy applications
is also supported.

See [project technical overview](http://www.openfastpath.org/index.php/service/technicaloverview/)
for more details about OpenFastPath architecture and main features.


Directory structure
-------------------------------------------------------------------------------
./config/      - Example configuration files<br>
./docs/        - This is where you can find more detailed documentation<br>
./example/     - Example applications that use the project library<br>
./include/api/ - Public interface headers used by an application.<br>
./include/     - Internal interface headers that are used in OFP library.<br>
./scripts/     - Auxiliary scripts.<br>
./src/         - .c files with OFP library implementation.<br>
./test/cunit/  - CUnit testcases implementation


Coding Style:
-------------------------------------------------------------------------------
Project code uses Linux kernel style that is verified through `checkpatch.pl`


Licensing:
-------------------------------------------------------------------------------
Project uses BSD 3-CLause License as default license. One should not use code
that is licensed under any GPL type.


OpenFastPathGen2 getting started
===============================================================================


Build environment preparation:
-------------------------------------------------------------------------------
This project is currently verified on a generic 64bit x86 Linux machine.

The following packages are mandatory for accessing and building ODP and OFP:

    git aclocal libtool automake build-essential pkg-config

The following packages are optional:

    libssl-dev doxygen asciidoc valgrind libcunit1 libcunit1-doc libcunit1-dev libconfig-dev

The usage of libconfig-dev package is enabled by default and can be disabled by --disable-libconfig
configure option.

Download and build OpenDataPlane (ODP) library:

    git clone https://github.com/OpenDataPlane/odp-dpdk
    cd odp-dpdk
    git checkout v1.25.2.0_DPDK_19.11
    ./bootstrap
    ./configure --prefix=<INSTALL ODP TO THIS DIR>
    make
    make install

(`make install` may require root permissions)

Instructions for building OFP on top of ODP-DPDK and ODP-ThunderX can be found
from OFP User Guide (`docs/ofp-user-guide.adoc`).


Building OFPgen2:
-------------------------------------------------------------------------------
    git clone https://github.com/bogdanPricope/ofp
    cd ofp
    ./bootstrap
    ./configure --prefix=<INSTALL OFP TO THIS DIR> --with-odp=<ODP INSTALLATION DIR>
    make
    make install 

Alternatively, a script can be used to generate a DPDK/ODP-DPDK/OFPgen2 build:
    git clone https://github.com/bogdanPricope/ofp
    cd ofp/scripts
	./devbuild_ofp_odp_dpdk.sh


OFPgen2 example applications:
-------------------------------------------------------------------------------
OpenFastPath project contains a number of example applications described in
`example/README` file. See OFP User Guide (`docs/ofp-user-guide.adoc`) for
more details about designing and executing OFP applications. 


ODP/DPDK recommended versions:
===============================================================================

OFPgen2 supports a wider variety of ODP and DPDK versions but recommended
(tested) versions are:
 - ODP-DPDK (https://github.com/OpenDataPlane/odp-dpdk) version 1.25.2,
 platform 'linux-generic'
  - DPDK version v18.11.


Tools
===============================================================================


Code coverage:
-------------------------------------------------------------------------------
Generate code coverage report from unit tests by passing `--coverage` during
building, and use `lcov` to view the results:

    ./configure <typical-ofp-flags> CFLAGS='-g -O0 --coverage' \
      LDFLAGS='--coverage'
    make check

    cd test/cunit

    lcov --directory . --directory ../../src --capture --output-file \
      coverage.info

    genhtml coverage.info --output-directory out

view `out/index.html`

