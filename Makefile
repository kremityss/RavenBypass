TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = RavenShield
RavenShield_FILES = Tweak.x fishhook.c
RavenShield_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
RavenShield_FRAMEWORKS = Foundation UIKit Security

include $(THEOS_MAKE_PATH)/tweak.mk
