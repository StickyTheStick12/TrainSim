import bisect
from heapq import merge
from datetime import datetime, timedelta

lst1 = [
    {
        "AdvertisedTime": "2023-11-03 07:12",
        "EstimatedTime": "2023-11-03 07:12",
        "TrackAtLocation": "1",
        "id": "1"
    },
    {
        "AdvertisedTime": "2023-11-03 07:16",
        "EstimatedTime": "2023-11-03 07:16",
        "TrackAtLocation": "6",
        "id": "2"
    }
]

lst2 = [
    {
        "AdvertisedTime": "2023-11-03 06:42",
        "EstimatedTime": "2023-11-03 06:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6"
    },
    {
        "AdvertisedTime": "2023-11-03 06:47",
        "EstimatedTime": "2023-11-03 06:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "3"
    },
    {
        "AdvertisedTime": "2023-11-03 07:42",
        "EstimatedTime": "2023-11-03 07:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6",
        "id": "2"
    },
    {
        "AdvertisedTime": "2023-11-03 07:47",
        "EstimatedTime": "2023-11-03 07:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "1",
        "id": "1"
    },
    {
        "AdvertisedTime": "2023-11-03 08:42",
        "EstimatedTime": "2023-11-03 08:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6"
    },
    {
        "AdvertisedTime": "2023-11-03 08:47",
        "EstimatedTime": "2023-11-03 08:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "1"
    },
    {
        "AdvertisedTime": "2023-11-03 09:42",
        "EstimatedTime": "2023-11-03 09:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6"
    },
    {
        "AdvertisedTime": "2023-11-03 09:47",
        "EstimatedTime": "2023-11-03 09:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "1"
    },
    {
        "AdvertisedTime": "2023-11-03 10:42",
        "EstimatedTime": "2023-11-03 10:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6"
    },
    {
        "AdvertisedTime": "2023-11-03 10:47",
        "EstimatedTime": "2023-11-03 10:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "1"
    },
    {
        "AdvertisedTime": "2023-11-03 11:42",
        "EstimatedTime": "2023-11-03 11:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6"
    },
    {
        "AdvertisedTime": "2023-11-03 11:47",
        "EstimatedTime": "2023-11-03 11:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "1"
    },
    {
        "AdvertisedTime": "2023-11-03 12:42",
        "EstimatedTime": "2023-11-03 12:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6"
    },
    {
        "AdvertisedTime": "2023-11-03 12:47",
        "EstimatedTime": "2023-11-03 12:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "1"
    },
    {
        "AdvertisedTime": "2023-11-03 13:42",
        "EstimatedTime": "2023-11-03 13:42",
        "ToLocation": "Emmaboda",
        "TrackAtLocation": "6"
    },
    {
        "AdvertisedTime": "2023-11-03 13:47",
        "EstimatedTime": "2023-11-03 13:47",
        "ToLocation": "K\u00f6penhamn",
        "TrackAtLocation": "1"
    }
]

existing_times_arrival = [datetime.strptime(item['EstimatedTime'], "%Y-%m-%d %H:%M") for item in lst1]
existing_times_departure = [datetime.strptime(item['EstimatedTime'], "%Y-%m-%d %H:%M") for item in lst2]

# Merge the two lists while keeping them sorted
merged_existing_times = list(merge(existing_times_arrival, existing_times_departure))

current_time = datetime.now()
today_date = current_time.date()
recv_time = "2023-12-15 17:27"

if recv_time < current_time:
    recv_time += timedelta(days=1)

# we wish to arrive 10 minutes before planned departure
advertised_arrival_time = datetime.strptime(recv_time, "%Y-%m-%d %H:%M") - timedelta(minutes=10)

# if the train should arrive in the past, schedule the train for arrival as soon as possible
if advertised_arrival_time < current_time:
    temp = current_time
else:
    temp = advertised_arrival_time

idx = bisect.bisect_left(merged_existing_times, temp)  # this should give us the index that is greater than or equal to the advertised time

is_found = False
best_idx = -1
best_time = None

# case 1: can be scheduled before all the other trains
if idx == 0:
    # calculate how much time there is between this arrival and the next switch update. To be on the safe side we will give it 4 minutes.
    # it should only need 3 minutes though
    difference = merged_existing_times[0] - temp - timedelta(minutes=1)

    if difference >= timedelta(minutes=4):
        train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                      'EstimatedTime': temp.strftime("%Y-%m-%d %H:%M"),
                      'TrackAtLocation': data[4],
                      'IsRemoved': False,
                      'TrainOwner': "hmi",
                      'id': str(available_id)}
        merged_existing_times.insert(0, train_data)
        is_found = True

if not is_found and idx != len(merged_existing_times) - 1:
    for _idx in range(len(merged_existing_times[idx:]) - 1):
        if merged_existing_times[_idx] + timedelta(minutes=1) - merged_existing_times[_idx + 1] - timedelta(
                minutes=2) > timedelta(minutes=4):
            if merged_existing_times[_idx] + timedelta(minutes=1) >= timedelta(minutes=4):
                temp = merged_existing_times[_idx] + timedelta(minutes=1)

                train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                              'EstimatedTime': temp.strftime("%Y-%m-%d %H:%M"),
                              'TrackAtLocation': data[4],
                              'IsRemoved': False,
                              'TrainOwner': "hmi",
                              'id': str(available_id)}
                merged_existing_times.insert(_idx, train_data)
                is_found = True
                break

if not is_found:
    temp = merged_existing_times[-1] + timedelta(minutes=1)

    train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                  'EstimatedTime': temp.strftime("%Y-%m-%d %H:%M"),
                  'TrackAtLocation': data[4],
                  'IsRemoved': False,
                  'TrainOwner': "hmi",
                  'id': str(available_id)}
    merged_existing_times.append(train_data)
    is_found = True

await write_to_file(arrival_data, 0)







# find the first available arrival time. This should be as close as possible to recv_time minus 10 minutes

# find the first available departure time. This should be as close as possible to the found arrival time

# This is the preferred time for the train to arrive.



estimated_arrival_time = current_time - advertised_arrival_time

# we need to check if 1. the preferred time is actually possible for us to arrive at. Otherwise we have to schedule the train to arrive now
# 2. Find the first possible time to arrive too. Preferably we don't reschedule an already existing train
# at least not more than 1 minute. We create a new list with all the times and subtract and add times.
# we then have to find the best time, as close to 10 minutes as possible. It is better to go after 9 minutes than wait 60 minutes
# or we can start reschedule all the hmi trains for them to better fit. So the advertised time is actual time we arrive and depart.


# check if the arrival time is possible for us to arrive at. preferably 10 minutes before wished but everything above 5 minutes is okay too
if estimated_arrival_time < timedelta(minutes=5):
    estimated_arrival_time = current_time + timedelta(minutes=10) - estimated_arrival_time

# we will try and find the most optimal arrival

idx = bisect.bisect_right(merged_existing_times, advertised_arrival_time)  # this should give us the index that is less than equal to the estiamted time

is_found = False
best_idx = -1
best_time = None

# case 1: can be scheduled before all the other trains
if idx == 0:
    # calculate how much time there is between this arrival and the next switch update. To be on the safe side we will give it 4 minutes.
    # it should only need 3 minutes though
    difference = merged_existing_times[0] - temp - timedelta(minutes=1)

    if difference >= timedelta(minutes=4):
        # schedule this train as early as possible
        if merged_existing_times[1] > estimated_arrival_time + timedelta(minutes=1):
            train_data = {'AdvertisedTime': temp.strftime("%Y-%m-%d %H:%M"),
                          'EstimatedTime': estimated_arrival_time.strftime("%Y-%m-%d %H:%M"),
                          'TrackAtLocation': data[4],
                          'IsRemoved': False,
                          'TrainOwner': "hmi",
                          'id': str(available_id)}
            merged_existing_times.append(train_data)
            is_found = True



elif idx == len(merged_existing_times) - 1:
    # schedule this train as early as possible
    estimated_arrival_time = merged_existing_times[idx] + timedelta(minutes=1)

    train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                  'EstimatedTime': estimated_arrival_time.strftime("%Y-%m-%d %H:%M"),
                  'TrackAtLocation': data[4],
                  'IsRemoved': False,
                  'TrainOwner': "hmi",
                  'id': str(available_id)}
    merged_existing_times.append(train_data)
    is_found = True

if not is_found:
    # case 2: need to be scheduled in between trains
    for idx in range(len(merged_existing_times[idx:]) - 1):
        if merged_existing_times[idx] + timedelta(minutes=1) - merged_existing_times[idx+1] - timedelta(minutes=2) > timedelta(0):
            # schedule this train as early as possible
            if merged_existing_times[idx] + timedelta(minutes=1) >= estimated_arrival_time:
                estimated_arrival_time = merged_existing_times[idx] + timedelta(minutes=1)

                train_data = {'AdvertisedTime': advertised_arrival_time.strftime("%Y-%m-%d %H:%M"),
                              'EstimatedTime': estimated_arrival_time.strftime("%Y-%m-%d %H:%M"),
                              'TrackAtLocation': data[4],
                              'IsRemoved': False,
                              'TrainOwner': "hmi",
                              'id': str(available_id)}
                merged_existing_times.insert(idx, train_data)
                break

await write_to_file(arrival_data, 0)






                train_data = {'AdvertisedTime': recv_time.strftime("%Y-%m-%d %H:%M"),
                              'EstimatedTime': recv_time.strftime("%Y-%m-%d %H:%M"),
                              'ToLocation': data[3],
                              'TrackAtLocation': data[4],
                              'IsRemoved': False,
                              'TrainOwner': "hmi",
                              'id': str(available_id)}

                existing_times = [datetime.strptime(item['EstimatedTime'], "%Y-%m-%d %H:%M") for item in departure_data]
                departure_index = bisect.bisect_right(existing_times, datetime.strptime(train_data['EstimatedTime'], "%Y-%m-%d %H:%M"))
                departure_data.insert(departure_index, train_data)

                await write_to_file(departure_data, 1)
                await departure_to_data()

                if arrival_index == 0:
                    if serving_arrival.is_set():
                        give_up_switch.set()
                    elif arrival_switch_request.is_set():
                        try:
                            temp = switch_queue.get_nowait()

                            if temp[0] != 0:
                                await switch_queue.put(temp)
                        except asyncio.QueueEmpty:
                            pass

                    _logger.info("h: woke arrival")
                    wake_arrival.set()

                if departure_index == 0:
                    if serving_departure.is_set():
                        give_up_switch.set()
                    elif departure_switch_request.is_set():
                        try:
                            temp = switch_queue.get_nowait()

                            if temp[0] != 0:
                                await switch_queue.put(temp)
                        except asyncio.QueueEmpty:
                            pass

                    _logger.info("h: woke departure")
                    wake_departure.set()

                for i in range(3, -1, -1):
                    modbus_data_queue.put(["B", str(i)])
                    entries_in_gui -= 1
                send_data.set()

                await departure_to_data()
