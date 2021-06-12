# ****************************************************************************
#    Ledger App Radix
#    (c) 2020 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
else
    $(error Environment variable 'BOLOS_SDK' is set, we expect it NOT to be. Instead set 'BOLOS_SDK_NANO_S' and 'BOLOS_SDK_NANO_X' respectively.\nTerminating build.)
    exit 1;
endif

ifeq ($(BOLOS_SDK_NANO_S),)
    ifeq ($(BOLOS_SDK_NANO_X),)
        $(error Neither Environment variable 'BOLOS_SDK_NANO_S' nor 'BOLOS_SDK_NANO_X' is not set.\nTerminating build.)
        exit 1;
    endif
endif

ifeq ($(CLANGPATH_NANO_S),)
    ifeq ($(CLANGPATH_NANO_X),)
        $(error Neither Environment variable 'CLANGPATH_NANO_S' nor 'CLANGPATH_NANO_X' is not set.\nTerminating build.)
        exit 1;
    endif
endif

ifeq ($(BOLOS_ENV),)
    $(error Environment variable 'BOLOS_ENV' was not found/is not set.\nTerminating build.)
    exit 1;
endif


ifeq ($(TARGET),NANOX)
TARGET_NAME=TARGET_NANOX
BOLOS_SDK=$(BOLOS_SDK_NANO_X)
$(info setting 'BOLOS_SDK' = 'BOLOS_SDK_NANO_X')
else
BOLOS_SDK=$(BOLOS_SDK_NANO_S)
$(info setting 'BOLOS_SDK' = 'BOLOS_SDK_NANO_S')
endif

ifeq ($(BOLOS_SDK),)
    $(error Environment variable 'BOLOS_SDK' was not found/is not set)
else
    $(info 'BOLOS_SDK' is set to: '$(BOLOS_SDK)')
endif

include $(BOLOS_SDK)/Makefile.defines

BIP44_COIN_TYPE_RADIX= "44'/536'"

APP_LOAD_PARAMS  = --curve secp256k1
APP_LOAD_PARAMS += --appFlags 0x240
APP_LOAD_PARAMS += --path $(BIP44_COIN_TYPE_RADIX)
APP_LOAD_PARAMS += $(COMMON_LOAD_PARAMS)

APPNAME      = "Radix"
APPVERSION_M = 0
APPVERSION_N = 3
APPVERSION_P = 1
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

ifeq ($(TARGET_NAME),TARGET_NANOX)
    ICONNAME=icons/nanox_app_radix.gif
else
    ICONNAME=icons/nanos_app_radix.gif
endif

all: default

DEFINES += $(DEFINES_LIB)
DEFINES += APPNAME=\"$(APPNAME)\"
DEFINES += APPVERSION=\"$(APPVERSION)\"
DEFINES += MAJOR_VERSION=$(APPVERSION_M) MINOR_VERSION=$(APPVERSION_N) PATCH_VERSION=$(APPVERSION_P)
DEFINES += OS_IO_SEPROXYHAL
DEFINES += HAVE_BAGL HAVE_UX_FLOW HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += USB_SEGMENT_SIZE=64
DEFINES += BLE_SEGMENT_SIZE=32
DEFINES += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""
DEFINES += UNUSED\(x\)=\(void\)x

ifeq ($(TARGET_NAME),TARGET_NANOX)
    DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=300
    DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000 HAVE_BLE_APDU
    DEFINES += HAVE_GLO096
    DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64
    DEFINES += HAVE_BAGL_ELLIPSIS
    DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
    DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
    DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
else
    DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=256 # Radix app uses 128
endif

DEBUG = 0
ifneq ($(DEBUG),0)
    DEFINES += HAVE_PRINTF
    ifeq ($(TARGET_NAME),TARGET_NANOX)
        DEFINES += PRINTF=mcu_usb_printf
    else
        DEFINES += PRINTF=screen_printf
    endif
else
        DEFINES += PRINTF\(...\)=
endif

ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
GCCPATH   := $(BOLOS_ENV)/gcc_nano_s_se200_and_nano_x_se124_compatible/bin/
endif


ifeq ($(TARGET),NANOX)
CLANGPATH := $(CLANGPATH_NANO_X)/bin/
$(info setting 'CLANGPATH' = 'CLANGPATH_NANO_X/bin')
else
CLANGPATH := $(CLANGPATH_NANO_S)/bin/
$(info setting 'CLANGPATH' = 'CLANGPATH_NANO_S/bin')
endif


CC      := $(CLANGPATH)clang
CFLAGS  += -O3 -Os
AS      := $(GCCPATH)arm-none-eabi-gcc
LD      := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS  += -lm -lgcc -lc

include $(BOLOS_SDK)/Makefile.glyphs

APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl lib_ux

ifeq ($(TARGET_NAME),TARGET_NANOX)
    SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
endif

load: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

load-offline: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS) --offline

delete:
	python3 -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN XRD
