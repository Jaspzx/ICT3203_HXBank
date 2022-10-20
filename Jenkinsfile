pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
						sh 'docker container rm --force ict3203_hxbank-flask'
						sh 'docker image rm --force ict3203_hxbank-flask'
						sh 'docker build -t ict3203_hxbank-flask .'
					}
				echo 'Build phase success'
			}
		}
		stage('Test') {
			steps {
				echo 'Testing'
			}
		}
		stage('OWASP DependencyCheck') {
			steps {
				dependencyCheck additionalArguments: '--format HTML --format XML', odcInstallation: 'OWASP Dependency Check'
			}
		}
	}	
	post {
		success {
			dependencyCheckPublisher pattern: 'dependency-check-report.xml'
		}
	}
}