SampleSecuredWebapp
===================

This sample web app can be used to send a GET or PUT request to a dataservice which is secured using X509 sign and encryption.

##Setting up the environment
Using the sample provided in DSS 3.2.1 create a dataservice and expose it as a RESTful service and enable X509 sign and encryption
based security for this service.

##Sending a request

eg: invoke web app to send a PUT request to the dataservice hosted in DSS

`curl -v -X GET "http://192.168.186.1:9773/SecuredSampleWebApp-1.0.0/SecuredSample?cmd=update&sal=8978"`

eg: invoke web app to send a GET request to the dataservice hosted in DSS

`curl -v -X GET "http://192.168.186.1:9773/SecuredSampleWebApp-1.0.0/SecuredSample?cmd=get"`
