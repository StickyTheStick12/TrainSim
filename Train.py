import asyncio
from datetime import datetime, timedelta

train = ["2023-11-28 07:47", "2023-11-28 07:59", asyncio.Event(), asyncio.Event(), 5, 0]  # arrivaltime, departure time, green_light, wakeup, track, train id when communicating with hmi


async def main_loop(a_queue: asyncio.Queue) -> None:
    advertised_time = datetime.strptime(train[0], "%Y-%m-%d %H:%M")

    request = [train[4], train[5]]

    await a_queue.put(" ".join(request).encode())

    await train[2].wait()

    logging.info("Train is clear to arrive")
    train[2].clear()

    if train[3].is_set():
        train[3].clear()
        logging.info("Wake arrival event has been set. Return switch")
        await a_queue.put(["Give up switch message"])
        # return to socket and wait until next time we use this socket for a train
        return

    updated_time = datetime.strptime(train[0], "%Y-%m-%d %H:%M")

    if updated_time == advertised_time:
        difference = (updated_time - datetime.now()).total_seconds()
        logging.info("Train is planned to arrive at the estimated tine")
        await asyncio.sleep(max(0, difference - 20))

        if train[3].is_set():
            logging.info("Function has been woken. Returning switch")
            train[3].clear()
            await a_queue.put(["Give up switch message"])
            return

    # should hopefully let us change the switch
    logging.info("Sleeping 20 seconds so we can change the switch")
    await asyncio.sleep(20)

    # Send an update that the train has now arrived
    a_queue(["Train has arrived message"])

    # message the correct sensor that we are now here

    a_queue(["Has changed sensor release mutex"])

    # departure
    departure_time = datetime.strptime(train[1], "%Y-%m-%d %H:%M")

    difference = departure_time - datetime.now()

    try:
        await asyncio.wait_for(train[3].wait(), timeout=max(0, difference.total_seconds() - 2 * 60))
        train[3].clear()
        logging.info("Received a wakeup call")
        return
    except asyncio.TimeoutError:
        logging.info("Timeout error")
        pass

    await a_queue.put(["I want the switch"])

    await train[2].wait()
    train[2].clear()

    if train[3].is_set():
        logging.info("Function has been woken. Returning swtich")
        train[3].clear()
        a_queue.put(["I want to return the switch"])
        return

    update_depart_time = datetime.strptime(train[1], "%Y-%m-%d %H:%M")

    if update_depart_time > departure_time:
        logging.info("Train is late, leaving in 20 seconds")

        try:
            await asyncio.wait_for(train[3], timeout=20)
            train[3].clear()
            await a_queue.put(["I want to return the switch"])
            logging.info("Received a wakeup call")
            return
        except asyncio.TimeoutError:
            logging.info("Timeout error")
            pass

        await a_queue.put(["i want to depart"])
        await asyncio.sleep(20)
    else:
        difference = update_depart_time - datetime.now()
        logging.info(f"sleeping {difference} seconds")

        try:
            await asyncio.wait_for(train[3].wait(), timeout=max(difference.total_seconds(), 0))
            train[3].clear()
            await a_queue.put(["I want to return the switch"])
            logging.info("Received a wakeup call")
            return
        except asyncio.TimeoutError:
            logging.info("Timeout error")
            pass

        await a_queue.put(["I wish to depart"])

        await asyncio.sleep(20)


async def write_data(writer: asyncio.StreamWriter, a_queue: asyncio.Queue):
    # task in handle_com_one
    while True:
        data = await a_queue.get()
        writer.write(data)
        await writer.drain()


async def handle_com_one(writer: asyncio.StreamWriter, reader: asyncio.StreamReader) -> None:
    # recv data from simulation. Decide what to do with said data
    loop = asyncio.new_event_loop()
    while True:
        data = await reader.read(1024)

        if data == "ABC":
            a_queue = asyncio.Queue()  # pass this to main_loop. Comm from main loop to socket. Socket to main loop through above variables
            loop.create_task(main_loop(a_queue))
