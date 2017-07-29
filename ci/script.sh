main() {
    local src=$(pwd) \
          stage=

    case $TRAVIS_OS_NAME in
        linux)
            stage=$(mktemp -d)
            ;;
        osx)
            stage=$(mktemp -d -t tmp)
            ;;
    esac

    docker build -t $CRATE_NAME $DOCKER_BUILD_CONTEXT
    docker run -e TARGETOS=$TARGETOS -e TARGETARCH=$TARGETARCH -v $stage:/target $CRATE_NAME

    cd $stage
    if [ $TARGETOS = windows ]; then
        zip -r $src/$CRATE_NAME-$TRAVIS_TAG-$TARGETOS-$TARGETARCH.zip *
    else
        tar czf $src/$CRATE_NAME-$TRAVIS_TAG-$TARGETOS-$TARGETARCH.tar.gz *
    fi
}

main
