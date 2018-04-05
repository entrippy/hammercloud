# hammercloud

## Overview

Drop in replacement for Homeassistants Cloud component.
Service consists of a websocket server to handle connections from HASS, and a rest API for recieving requests from google assistance and Amazon Alexa

## Requirements

### AWS

Cognito UserPool
EC2 instance
ALB (for https offload)

### Google 
Things

## TODO
Return reply message from sock handler through to Google Assistant
Any and all Alexa stuff.
