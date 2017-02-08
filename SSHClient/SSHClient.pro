TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp
LIBS += -lssh

include(deployment.pri)
qtcAddDeployment()

