pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker-compose down --rmi local'
						sh 'docker-compose up -d'
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