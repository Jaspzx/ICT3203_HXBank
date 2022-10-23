pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker compose stop flask'
                        sh 'docker compose stop nginx'
                        sh 'docker compose rm -f flask'
                        sh 'docker image rm -f ict3203_hxbank-flask'
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
                    sh 'docker compose start nginx'
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