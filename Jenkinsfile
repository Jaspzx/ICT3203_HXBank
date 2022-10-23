pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker container rm -f flask'
                        sh 'docker image rm -f ict3203_hxbank-flask'
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

		stage ('Deploy') {
            steps {
                script{
                    sh 'docker container run -d --expose 5000  --v ../instance/:/app/instance/ --env-file .env --name flask ict3203_hxbank-flask'
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