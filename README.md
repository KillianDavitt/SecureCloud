# Secure Cloud
[![Build Status](https://travis-ci.org/KillianDavitt/SecureCloud.svg?branch=master)](https://travis-ci.org/KillianDavitt/SecureCloud)
[![Go Report Card](https://goreportcard.com/badge/github.com/KillianDavitt/SecureCloud)](https://goreportcard.com/report/github.com/KillianDavitt/SecureCloud)

A file encryption application for https://www.github.com/KillianDavitt/ClassCloud

Uses AES256 bit encryption to encrypt your files before uploading them to an instance of 'ClassCloud'

# Introduction
The application consists of two programs, both written in go; the user application and the key server.
Both of these programs interact both with each other as well as with the cloud server itself.
The cloud server must be an instance of 'ClassCloud'

# Application Architecture

![architecture diagram](https://raw.githubusercontent.com/KillianDavitt/SecureCloud/master/doc/architecture.jpg)

