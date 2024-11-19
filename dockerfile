FROM mcr.microsoft.com/dotnet/sdk:8.0.204-alpine3.19-amd64 AS build
WORKDIR /src
COPY ./Intelica.Authentication.Backend ./
RUN dotnet publish ./Intelica.Authentication.API/Intelica.Authentication.API.csproj --framework net8.0 -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:8.0.4-alpine3.19-amd64
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
ENV TZ=America/Lima
ENV ASPNETCORE_ENVIRONMENT=Docker
RUN apk update && apk add libgdiplus icu-libs libc6-compat tzdata
EXPOSE 8080
ENV ASPNETCORE_URLS=http://*:8080
WORKDIR /app
RUN mkdir Documents
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Intelica.Authentication.API.dll"]