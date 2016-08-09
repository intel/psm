node('master') {
    try {
        stage 'Checkout'
            checkout scm
        stage 'Version Check'
            sh 'gcc --version'
            sh 'make --version'
        stage 'Build'
            sh 'make'
        stage 'Install'
            env.DESTDIR = "${env.PWD}/test-install"
            sh 'make install'
        currentBuild.result = "SUCCESS"
    } catch (err) {
        currentBuild.result = "FAILURE"
        throw err
    }
}
