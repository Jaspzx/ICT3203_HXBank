pipeline {
	agent any
	environment {
	    env_file = credentials('env')
	}
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker container rm -f flask'
                        sh 'docker image rm -f flask'
                        sh 'docker build -t flask .'
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
                    sh 'docker container run -d --expose 5000 -v /home/Team-13/webportal/ICT3203_HXBank/db/:/etc/certs/ -w /app --env-file $env_file --network HXBank_bridge --ip 172.30.0.2 --network-alias flask --name flask flask'
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