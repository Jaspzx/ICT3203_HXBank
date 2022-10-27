pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker container rm -f flask'
                        sh 'docker image rm -f flask'
                        sh 'docker compose build flask'
					}
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

		stage ('Deploy') {
            steps {
                script{
                    sh 'docker compose up -d flask'
                }
            }
        }
	}	
	post {
		success {
			dependencyCheckPublisher pattern: 'dependency-check-report.xml'
		}
	}
}