import java.util.concurrent.Semaphore;

public class Rdv {

	Semaphore mutex;
	Integer nbrThread;

	public Rdv(Integer nbrThread) {
		this.mutex = new Semaphore(nbrThread - 1);
		this.nbrThread = nbrThread;
	}

	public void rdv() {
		try {
			synchronized (this) {
				if (mutex.tryAcquire()) {
					this.wait();
				}
				this.notifyAll();
			}
			mutex.release();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public int token() {
		return mutex.availablePermits();
	}
}
