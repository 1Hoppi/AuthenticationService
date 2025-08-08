# Authentication microservice

This repository contains a C# .NET web application that's responsible for easy and memory-friendly authentication. JWT Tokens that're partly stored as blacklist in Redis. It supports the most important endpoints:
### Login - Register - Refresh - Logout - LogoutAll

## Building the Project

Pay close attention to the installed libraries. Personal NuGet libs are presented meaning there's a change of not being compatible (so far I haven't met any issues on win11 and LTS Ubuntu 22-24)
To build the project, run the following command in the root:

```bash
dotnet build
```
## Issues

At start or after making changed to the project (especially to .proto files), you might need to go through some dependency updating sequences.
Try using one of these commands:

```bash
dotnet nuget locals all --clear
dotnet clear
dotnet restore
```
that follows by:

```bash
dotnet build
```
or running all of them one by one.
