pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker container rm -f flask'
                        SH 'docker image rm -f hxbankpipeline-flask'
                        sh 'docker compose build flask'
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